package main

import (
	"fmt"
)

func alertLinkRawText(ai *AdvisoryItem) string {
	if ai.AlertNumber == 0 {
		return ""
	}
	return fmt.Sprintf("#%d", ai.AlertNumber)
}

func (ai *AdvisoryItem) printLine(alertTypeWidth, dependabotLinkWidth, identifierWidth, severityWidth int, formatter Formatter) {
	alertType := formatter.FormatAlertType(ai)
	alertTypePadding := alertTypeWidth - len(ai.AlertType)
	dependabotLink := formatter.FormatAlertLink(ai)
	dependabotLinkPadding := dependabotLinkWidth - len(alertLinkRawText(ai))
	identifier := formatter.FormatIdentifier(ai)
	identifierPadding := identifierWidth - len(ai.Identifier)
	severity := formatter.FormatSeverity(ai)
	severityPadding := severityWidth - len(ai.Severity)
	createdAt := formatter.FormatCreatedAt(ai)
	summary := formatter.FormatSummary(ai)

	fmt.Printf("%s%-*s %s%-*s %s%-*s %s%-*s %s %s\n",
		alertType, alertTypePadding+1, "",
		dependabotLink, dependabotLinkPadding+1, "",
		identifier, identifierPadding+1, "",
		severity, severityPadding+1, "",
		createdAt,
		summary)
}

func (ri *RepositoryItem) printList(opts *Options) {
	formatter := NewFormatter(opts.NoColor)

	alertTypeWidth := 0
	dependabotLinkWidth := 0
	identifierWidth := 0
	severityWidth := 0

	for _, advisory := range ri.AdvisoryItems {
		if len(advisory.AlertType) > alertTypeWidth {
			alertTypeWidth = len(advisory.AlertType)
		}
		if l := len(alertLinkRawText(&advisory)); l > dependabotLinkWidth {
			dependabotLinkWidth = l
		}
		if len(advisory.Identifier) > identifierWidth {
			identifierWidth = len(advisory.Identifier)
		}
		if len(advisory.Severity) > severityWidth {
			severityWidth = len(advisory.Severity)
		}
	}

	fmt.Printf("# %s\n", formatter.FormatRepositoryName(ri.Name))

	for _, advisory := range ri.AdvisoryItems {
		advisory.printLine(alertTypeWidth, dependabotLinkWidth, identifierWidth, severityWidth, formatter)
	}
}

func printResult(repositories []RepositoryItem, opts *Options) {
	for _, repo := range repositories {
		repo.printList(opts)
		fmt.Println()
	}
}
