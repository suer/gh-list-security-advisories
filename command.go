package main

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"sync"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/spf13/cobra"
)

type Options struct {
	NoColor        bool
	Verbose        bool
	Excludes       []string
	Limit          int
	Severities     []string
	Show           string
	CodeScanning   bool
	SecretScanning bool
}

func rootCmd() *cobra.Command {
	opts := &Options{}
	version := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		version = info.Main.Version
	}
	cmd := &cobra.Command{
		Use:           "gh list-security-advisories <owner> [<owner>...]",
		Short:         "List security advisories for one or more owners' repositories",
		Version:       version,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Show == "" && len(args) < 1 {
				return errors.New("requires at least 1 owner argument")
			}
			// Suppress the usage dump for errors raised past argument
			// validation (e.g. a temp-log pointer from run()); it would
			// otherwise bury that message under a wall of flag help text.
			cmd.SilenceUsage = true
			if opts.Show != "" {
				return showAdvisory(opts.Show, opts)
			}
			return run(args, opts)
		},
	}
	cmd.SetVersionTemplate("{{.Version}}\n")

	cmd.Flags().StringArrayVarP(&opts.Excludes, "exclude", "e", []string{}, "exclude repositories")
	cmd.Flags().IntVarP(&opts.Limit, "limit", "l", 100, "Max number of vulnerability alerts to fetch per repository")
	cmd.Flags().StringArrayVarP(&opts.Severities, "severity", "s", []string{}, "filter by severity (CRITICAL, HIGH, MODERATE, LOW)")
	cmd.Flags().StringVar(&opts.Show, "show", "", "show details of a specific GHSA ID")
	cmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "disable color output")
	cmd.Flags().BoolVarP(&opts.Verbose, "verbose", "v", false, "verbose output")
	cmd.Flags().BoolVar(&opts.CodeScanning, "codescanning", false, "also collect code scanning alerts")
	cmd.Flags().BoolVar(&opts.SecretScanning, "secretscanning", false, "also collect secret scanning alerts")

	cmd.InitDefaultVersionFlag()
	cmd.Flags().Lookup("version").Usage = "show version"

	return cmd
}

func run(owners []string, opts *Options) error {
	gqlClient, err := api.DefaultGraphQLClient()
	if err != nil {
		return err
	}
	restClient, err := api.DefaultRESTClient()
	if err != nil {
		return err
	}

	pb := NewProgressBar()
	pb.Start()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allRepositories []RepositoryItem
	var errs []error

	for _, owner := range owners {
		wg.Add(1)
		go func(owner string) {
			defer wg.Done()

			repositories, err := fetchSecurityAdvisories(gqlClient, restClient, owner, opts, pb)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				errs = append(errs, err)
			}
			allRepositories = append(allRepositories, repositories...)
		}(owner)
	}

	wg.Wait()
	pb.Stop()

	printResult(allRepositories, opts)

	if len(errs) > 0 {
		joined := errors.Join(errs...)
		path, writeErr := writeErrorLog(joined)
		if writeErr != nil {
			return joined
		}
		return fmt.Errorf("some alerts may be missing due to errors; see %s for details", path)
	}

	return nil
}

// writeErrorLog writes err to a temp file instead of dumping it to the
// terminal, since a single rate-limited or unsupported-feature response can
// fan out into dozens of near-identical per-repository errors that would
// otherwise bury the successfully fetched results printed above.
func writeErrorLog(err error) (string, error) {
	f, createErr := os.CreateTemp("", "gh-list-security-advisories-errors-*.log")
	if createErr != nil {
		return "", createErr
	}
	defer f.Close()
	if _, writeErr := f.WriteString(err.Error() + "\n"); writeErr != nil {
		return "", writeErr
	}
	return f.Name(), nil
}
