package main

import (
	"sync"

	"github.com/spf13/cobra"
)

type Options struct {
	NoColor bool
	Verbose bool
}

func rootCmd() *cobra.Command {
	opts := &Options{}
	cmd := &cobra.Command{
		Use:           "gh list-security-advisories <owner> [<owner>...]",
		Short:         "List security advisories for one or more owners' repositories",
		Args:          cobra.MinimumNArgs(1),
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			owners := args
			return run(owners, opts)
		},
	}

	cmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "disable color output")
	cmd.Flags().BoolVarP(&opts.Verbose, "verbose", "v", false, "verbose output")

	return cmd
}

func run(owners []string, opts *Options) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var allRepositories []RepositoryItem
	var firstError error

	for _, owner := range owners {
		wg.Add(1)
		go func(owner string) {
			defer wg.Done()

			repositories, err := fetchSecurityAdvisories(owner)

			mu.Lock()
			defer mu.Unlock()

			if err != nil && firstError == nil {
				firstError = err
				return
			}

			allRepositories = append(allRepositories, repositories...)
		}(owner)
	}

	wg.Wait()

	if firstError != nil {
		return firstError
	}

	printResult(allRepositories, opts)

	return nil
}
