package main

import (
	"fmt"
)

func (ai *AdvisoryItem) printLine(alertTypeWidth, ghsaIdWidth, severityWidth int, formatter Formatter) {
	alertType := formatter.FormatAlertType(ai)
	alertTypePadding := alertTypeWidth - len(ai.AlertType)
	ghsaId := formatter.FormatGhsaId(ai)
	ghsaIdPadding := ghsaIdWidth - len(ai.GhsaId)
	severity := formatter.FormatSeverity(ai)
	severityPadding := severityWidth - len(ai.Severity)
	createdAt := formatter.FormatCreatedAt(ai)
	summary := formatter.FormatSummary(ai)

	fmt.Printf("%s%-*s %s%-*s %s%-*s %s %s\n",
		alertType, alertTypePadding+1, "",
		ghsaId, ghsaIdPadding+1, "",
		severity, severityPadding+1, "",
		createdAt,
		summary)
}

func (ri *RepositoryItem) printList(opts *Options) {
	formatter := NewFormatter(opts.NoColor)

	alertTypeWidth := 0
	ghsaIdWidth := 0
	severityWidth := 0

	for _, advisory := range ri.AdvisoryItems {
		if len(advisory.AlertType) > alertTypeWidth {
			alertTypeWidth = len(advisory.AlertType)
		}
		if len(advisory.GhsaId) > ghsaIdWidth {
			ghsaIdWidth = len(advisory.GhsaId)
		}
		if len(advisory.Severity) > severityWidth {
			severityWidth = len(advisory.Severity)
		}
	}

	fmt.Printf("# %s\n", formatter.FormatRepositoryName(ri.Name))

	for _, advisory := range ri.AdvisoryItems {
		advisory.printLine(alertTypeWidth, ghsaIdWidth, severityWidth, formatter)
	}
}

func printResult(repositories []RepositoryItem, opts *Options) {
	for _, repo := range repositories {
		repo.printList(opts)
		fmt.Println()
	}
}
