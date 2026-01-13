package main

import (
	"errors"
	"sync"

	"github.com/spf13/cobra"
)

type Options struct {
	NoColor    bool
	Verbose    bool
	Excludes   *[]string
	Limit      int
	Severities *[]string
	Show       string
}

func rootCmd() *cobra.Command {
	opts := &Options{Excludes: &[]string{}, Severities: &[]string{}}
	cmd := &cobra.Command{
		Use:           "gh list-security-advisories <owner> [<owner>...]",
		Short:         "List security advisories for one or more owners' repositories",
		SilenceErrors: true,
		Args: func(cmd *cobra.Command, args []string) error {
			if opts.Show != "" {
				return nil
			}
			if len(args) < 1 {
				return errors.New("requires at least 1 owner argument")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Show != "" {
				return showAdvisory(opts.Show, opts)
			}
			owners := args
			return run(owners, opts)
		},
	}

	cmd.Flags().StringArrayVarP(opts.Excludes, "exclude", "e", []string{}, "exclude repositories")
	cmd.Flags().IntVarP(&opts.Limit, "limit", "l", 100, "Max number of vulnerability alerts to fetch per repository")
	cmd.Flags().StringArrayVarP(opts.Severities, "severity", "s", []string{}, "filter by severity (CRITICAL, HIGH, MODERATE, LOW)")
	cmd.Flags().StringVar(&opts.Show, "show", "", "show details of a specific GHSA ID")
	cmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "disable color output")
	cmd.Flags().BoolVarP(&opts.Verbose, "verbose", "v", false, "verbose output")

	return cmd
}

func run(owners []string, opts *Options) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var allRepositories []RepositoryItem
	var errs []error

	for _, owner := range owners {
		wg.Add(1)
		go func(owner string) {
			defer wg.Done()

			repositories, err := fetchSecurityAdvisories(owner, opts)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				errs = append(errs, err)
				return
			}

			allRepositories = append(allRepositories, repositories...)
		}(owner)
	}

	wg.Wait()

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	printResult(allRepositories, opts)

	return nil
}
