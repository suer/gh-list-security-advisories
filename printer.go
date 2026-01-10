package main

import (
	"fmt"
)

func (ai *AdvisoryItem) printLine(ghsaIdWidth int, severityWidth int, createdAtWidth int, formatter Formatter) {
	ghsaId := formatter.FormatGhsaId(ai)
	ghsaIdPadding := ghsaIdWidth - len(ai.GhsaId)
	severity := formatter.FormatSeverity(ai)
	severityPadding := severityWidth - len(ai.Severity)
	createdAt := formatter.FormatCreatedAt(ai)
	summary := formatter.FormatSummary(ai)

	fmt.Printf("%s%-*s %s%-*s %s %s\n",
		ghsaId, ghsaIdPadding+1, "",
		severity, severityPadding+1, "",
		createdAt,
		summary)
}

func (ri *RepositoryItem) printList(opts *Options) {
	formatter := NewFormatter(opts.NoColor)

	ghsaIdWidth := 0
	severityWidth := 0
	createdAtWidth := len("2006-01-02")

	for _, advisory := range ri.AdvisoryItems {
		ghsaWidth := len(advisory.GhsaId)
		if ghsaWidth > ghsaIdWidth {
			ghsaIdWidth = ghsaWidth
		}

		sevWidth := len(advisory.Severity)
		if sevWidth > severityWidth {
			severityWidth = sevWidth
		}
	}

	fmt.Printf("# %s\n", formatter.FormatRepositoryName(ri.Name))

	for _, advisory := range ri.AdvisoryItems {
		advisory.printLine(ghsaIdWidth, severityWidth, createdAtWidth, formatter)
	}
}

func printResult(repositories []RepositoryItem, opts *Options) {
	for _, repo := range repositories {
		repo.printList(opts)
		fmt.Println()
	}
}
