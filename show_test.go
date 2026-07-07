package main

import (
	"strings"
	"testing"
)

// showAdvisory builds an AdvisoryItem with only Identifier and Severity set
// (a zero-value AlertType) to reuse Formatter for its output. Verify that
// combination still resolves to the advisories page URL, matching the
// behavior previously hard-coded into this package's own formatting
// functions.
func TestFormatterForShowAdvisory(t *testing.T) {
	item := &AdvisoryItem{Identifier: "GHSA-xxxx", Severity: "HIGH"}

	t.Run("NoColorFormatter", func(t *testing.T) {
		ncf := &NoColorFormatter{}
		if got := ncf.FormatIdentifier(item); got != "GHSA-xxxx" {
			t.Errorf("FormatIdentifier() = %q, want %q", got, "GHSA-xxxx")
		}
		if got := ncf.FormatSeverity(item); got != "HIGH" {
			t.Errorf("FormatSeverity() = %q, want %q", got, "HIGH")
		}
	})

	t.Run("ColorFormatter", func(t *testing.T) {
		cf := &ColorFormatter{}
		got := cf.FormatIdentifier(item)
		if !strings.Contains(got, "GHSA-xxxx") {
			t.Errorf("FormatIdentifier() = %q, should contain Identifier", got)
		}
		if !strings.Contains(got, "https://github.com/advisories/GHSA-xxxx") {
			t.Errorf("FormatIdentifier() = %q, should link to the advisories page for a zero-value AlertType", got)
		}
		if got := cf.FormatSeverity(item); !strings.Contains(got, "HIGH") {
			t.Errorf("FormatSeverity() = %q, should contain %q", got, "HIGH")
		}
	})
}
