package main

import (
	"strings"
	"testing"
)

func TestFormatGhsaIdForShow(t *testing.T) {
	if got := formatGhsaIdForShow("GHSA-xxxx", true); got != "GHSA-xxxx" {
		t.Errorf("formatGhsaIdForShow(noColor=true) = %q, want %q", got, "GHSA-xxxx")
	}
	if got := formatGhsaIdForShow("GHSA-xxxx", false); !strings.Contains(got, "GHSA-xxxx") {
		t.Errorf("formatGhsaIdForShow(noColor=false) = %q, should contain GhsaId", got)
	}
}

func TestFormatSeverityForShow(t *testing.T) {
	for _, severity := range []string{"CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"} {
		if got := formatSeverityForShow(severity, true); got != severity {
			t.Errorf("formatSeverityForShow(%q, noColor=true) = %q, want %q", severity, got, severity)
		}
		if got := formatSeverityForShow(severity, false); !strings.Contains(got, severity) {
			t.Errorf("formatSeverityForShow(%q, noColor=false) = %q, should contain %q", severity, got, severity)
		}
	}
}
