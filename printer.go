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

type columnWidths struct {
	alertType  int
	alertLink  int
	identifier int
	severity   int
}

func (ai *AdvisoryItem) printLine(widths columnWidths, formatter Formatter) {
	alertType := formatter.FormatAlertType(ai)
	alertTypePadding := widths.alertType - len(ai.AlertType)
	alertLink := formatter.FormatAlertLink(ai)
	alertLinkPadding := widths.alertLink - len(alertLinkRawText(ai))
	identifier := formatter.FormatIdentifier(ai)
	identifierPadding := widths.identifier - len(ai.Identifier)
	severity := formatter.FormatSeverity(ai)
	severityPadding := widths.severity - len(ai.Severity)
	createdAt := formatter.FormatCreatedAt(ai)
	summary := formatter.FormatSummary(ai)

	fmt.Printf("%s%-*s %s%-*s %s%-*s %s%-*s %s %s\n",
		alertType, alertTypePadding+1, "",
		alertLink, alertLinkPadding+1, "",
		identifier, identifierPadding+1, "",
		severity, severityPadding+1, "",
		createdAt,
		summary)
}

func (ri *RepositoryItem) printList(opts *Options) {
	formatter := NewFormatter(opts.NoColor)

	var widths columnWidths

	for _, advisory := range ri.AdvisoryItems {
		if len(advisory.AlertType) > widths.alertType {
			widths.alertType = len(advisory.AlertType)
		}
		if l := len(alertLinkRawText(&advisory)); l > widths.alertLink {
			widths.alertLink = l
		}
		if len(advisory.Identifier) > widths.identifier {
			widths.identifier = len(advisory.Identifier)
		}
		if len(advisory.Severity) > widths.severity {
			widths.severity = len(advisory.Severity)
		}
	}

	fmt.Printf("# %s\n", formatter.FormatRepositoryName(ri.Name))

	for _, advisory := range ri.AdvisoryItems {
		advisory.printLine(widths, formatter)
	}
}

func printResult(repositories []RepositoryItem, opts *Options) {
	for _, repo := range repositories {
		repo.printList(opts)
		fmt.Println()
	}
}
