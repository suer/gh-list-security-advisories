package main

import (
	"fmt"
	"time"

	"github.com/logrusorgru/aurora/v4"
)

type Formatter interface {
	FormatGhsaId(ai *AdvisoryItem) string
	FormatSeverity(ai *AdvisoryItem) string
	FormatCreatedAt(ai *AdvisoryItem) string
	FormatSummary(ai *AdvisoryItem) string
	FormatRepositoryName(name string) string
}

type ColorFormatter struct{}

func (cf *ColorFormatter) FormatGhsaId(ai *AdvisoryItem) string {
	url := fmt.Sprintf("https://github.com/advisories/%s", ai.GhsaId)
	return aurora.Cyan(ai.GhsaId).Hyperlink(url).String()
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
	return aurora.Bold(name).String()
}

type NoColorFormatter struct{}

func (ncf *NoColorFormatter) FormatGhsaId(ai *AdvisoryItem) string {
	return ai.GhsaId
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
