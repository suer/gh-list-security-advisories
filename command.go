package main

import (
	"github.com/spf13/cobra"
)

type Options struct {
	NoColor bool
	Verbose bool
}

func rootCmd() *cobra.Command {
	opts := &Options{}
	cmd := &cobra.Command{
		Use:           "gh list-security-advisories <owner>",
		Short:         "List security advisories for an owner's repositories",
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			owner := args[0]
			return run(owner, opts)
		},
	}

	cmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "disable color output")
	cmd.Flags().BoolVarP(&opts.Verbose, "verbose", "v", false, "verbose output")

	return cmd
}

func run(owner string, opts *Options) error {
	repositories, err := fetchSecurityAdvisories(owner)
	if err != nil {
		return err
	}

	printResult(repositories, opts)

	return nil
}
