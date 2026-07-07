package main

import (
	"fmt"
	"time"

	"github.com/logrusorgru/aurora/v4"
)

type Formatter interface {
	FormatAlertType(ai *AdvisoryItem) string
	FormatIdentifier(ai *AdvisoryItem) string
	FormatAlertLink(ai *AdvisoryItem) string
	FormatSeverity(ai *AdvisoryItem) string
	FormatCreatedAt(ai *AdvisoryItem) string
	FormatSummary(ai *AdvisoryItem) string
	FormatRepositoryName(name string) string
}

type ColorFormatter struct{}

func (cf *ColorFormatter) FormatAlertType(ai *AdvisoryItem) string {
	switch ai.AlertType {
	case "code-scanning":
		return aurora.Blue(ai.AlertType).String()
	case "secret-scanning":
		return aurora.Magenta(ai.AlertType).String()
	case "malware":
		return aurora.Red(ai.AlertType).String()
	default:
		return aurora.Cyan(ai.AlertType).String()
	}
}

func (cf *ColorFormatter) FormatIdentifier(ai *AdvisoryItem) string {
	var url string
	switch ai.AlertType {
	case "code-scanning":
		url = fmt.Sprintf("https://github.com/%s/security/code-scanning/%d", ai.RepositoryName, ai.AlertNumber)
	case "secret-scanning":
		url = fmt.Sprintf("https://github.com/%s/security/secret-scanning/%d", ai.RepositoryName, ai.AlertNumber)
	case "malware", "dependabot":
		url = fmt.Sprintf("https://github.com/advisories/%s", ai.Identifier)
	default:
		url = fmt.Sprintf("https://github.com/advisories/%s", ai.Identifier)
	}
	return aurora.Cyan(ai.Identifier).Hyperlink(url).String()
}

func alertLinkURL(ai *AdvisoryItem) string {
	switch ai.AlertType {
	case "code-scanning":
		return fmt.Sprintf("https://github.com/%s/security/code-scanning/%d", ai.RepositoryName, ai.AlertNumber)
	case "secret-scanning":
		return fmt.Sprintf("https://github.com/%s/security/secret-scanning/%d", ai.RepositoryName, ai.AlertNumber)
	case "malware":
		return fmt.Sprintf("https://github.com/%s/security/malware/%d", ai.RepositoryName, ai.AlertNumber)
	default:
		return fmt.Sprintf("https://github.com/%s/security/dependabot/%d", ai.RepositoryName, ai.AlertNumber)
	}
}

func (cf *ColorFormatter) FormatAlertLink(ai *AdvisoryItem) string {
	if ai.AlertNumber == 0 {
		return ""
	}
	return aurora.Cyan(fmt.Sprintf("#%d", ai.AlertNumber)).Hyperlink(alertLinkURL(ai)).String()
}

func (cf *ColorFormatter) FormatSeverity(ai *AdvisoryItem) string {
	switch ai.Severity {
	case "CRITICAL":
		return aurora.Red(ai.Severity).Bold().String()
	case "HIGH":
		return aurora.Red(ai.Severity).String()
	case "MODERATE":
		return aurora.Yellow(ai.Severity).String()
	case "LOW":
		return aurora.Green(ai.Severity).String()
	default:
		return ai.Severity
	}
}

func (cf *ColorFormatter) FormatCreatedAt(ai *AdvisoryItem) string {
	return ai.CreatedAt.In(time.Local).Format("2006-01-02")
}

func (cf *ColorFormatter) FormatSummary(ai *AdvisoryItem) string {
	return ai.Summary
}

func (cf *ColorFormatter) FormatRepositoryName(name string) string {
	url := fmt.Sprintf("https://github.com/%s", name)
	return aurora.Bold(name).Hyperlink(url).String()
}

type NoColorFormatter struct{}

func (ncf *NoColorFormatter) FormatAlertType(ai *AdvisoryItem) string {
	return ai.AlertType
}

func (ncf *NoColorFormatter) FormatIdentifier(ai *AdvisoryItem) string {
	return ai.Identifier
}

func (ncf *NoColorFormatter) FormatAlertLink(ai *AdvisoryItem) string {
	if ai.AlertNumber == 0 {
		return ""
	}
	return fmt.Sprintf("#%d", ai.AlertNumber)
}

func (ncf *NoColorFormatter) FormatSeverity(ai *AdvisoryItem) string {
	return ai.Severity
}

func (ncf *NoColorFormatter) FormatCreatedAt(ai *AdvisoryItem) string {
	return ai.CreatedAt.In(time.Local).Format("2006-01-02")
}

func (ncf *NoColorFormatter) FormatSummary(ai *AdvisoryItem) string {
	return ai.Summary
}

func (ncf *NoColorFormatter) FormatRepositoryName(name string) string {
	return name
}

func NewFormatter(noColor bool) Formatter {
	if noColor {
		return &NoColorFormatter{}
	}
	return &ColorFormatter{}
}
