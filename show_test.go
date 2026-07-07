package main

import (
	"strings"
	"testing"
)

// showAdvisory builds an AdvisoryItem with only GhsaId and Severity set (a
// zero-value AlertType) to reuse Formatter for its output. Verify that
// combination still resolves to the advisories page URL, matching the
// behavior previously hard-coded into this package's own formatting
// functions.
func TestFormatterForShowAdvisory(t *testing.T) {
	item := &AdvisoryItem{GhsaId: "GHSA-xxxx", Severity: "HIGH"}

	t.Run("NoColorFormatter", func(t *testing.T) {
		ncf := &NoColorFormatter{}
		if got := ncf.FormatGhsaId(item); got != "GHSA-xxxx" {
			t.Errorf("FormatGhsaId() = %q, want %q", got, "GHSA-xxxx")
		}
		if got := ncf.FormatSeverity(item); got != "HIGH" {
			t.Errorf("FormatSeverity() = %q, want %q", got, "HIGH")
		}
	})

	t.Run("ColorFormatter", func(t *testing.T) {
		cf := &ColorFormatter{}
		got := cf.FormatGhsaId(item)
		if !strings.Contains(got, "GHSA-xxxx") {
			t.Errorf("FormatGhsaId() = %q, should contain GhsaId", got)
		}
		if !strings.Contains(got, "https://github.com/advisories/GHSA-xxxx") {
			t.Errorf("FormatGhsaId() = %q, should link to the advisories page for a zero-value AlertType", got)
		}
		if got := cf.FormatSeverity(item); !strings.Contains(got, "HIGH") {
			t.Errorf("FormatSeverity() = %q, should contain %q", got, "HIGH")
		}
	})
}
