package main

import (
	"strings"
	"testing"
	"time"
)

func TestNewFormatter(t *testing.T) {
	if _, ok := NewFormatter(true).(*NoColorFormatter); !ok {
		t.Errorf("NewFormatter(true) should return *NoColorFormatter")
	}
	if _, ok := NewFormatter(false).(*ColorFormatter); !ok {
		t.Errorf("NewFormatter(false) should return *ColorFormatter")
	}
}

func TestNoColorFormatter(t *testing.T) {
	ncf := &NoColorFormatter{}
	ai := &AdvisoryItem{
		AlertType:      "dependabot",
		AlertNumber:    5,
		Identifier:     "GHSA-xxxx",
		Summary:        "some summary",
		Severity:       "HIGH",
		CreatedAt:      time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		RepositoryName: "owner/repo",
	}

	if got := ncf.FormatAlertType(ai); got != "dependabot" {
		t.Errorf("FormatAlertType() = %q, want %q", got, "dependabot")
	}
	if got := ncf.FormatIdentifier(ai); got != "GHSA-xxxx" {
		t.Errorf("FormatIdentifier() = %q, want %q", got, "GHSA-xxxx")
	}
	if got := ncf.FormatAlertLink(ai); got != "#5" {
		t.Errorf("FormatAlertLink() = %q, want %q", got, "#5")
	}
	if got := ncf.FormatSeverity(ai); got != "HIGH" {
		t.Errorf("FormatSeverity() = %q, want %q", got, "HIGH")
	}
	if got := ncf.FormatCreatedAt(ai); got != "2026-01-02" {
		t.Errorf("FormatCreatedAt() = %q, want %q", got, "2026-01-02")
	}
	if got := ncf.FormatSummary(ai); got != "some summary" {
		t.Errorf("FormatSummary() = %q, want %q", got, "some summary")
	}
	if got := ncf.FormatRepositoryName("owner/repo"); got != "owner/repo" {
		t.Errorf("FormatRepositoryName() = %q, want %q", got, "owner/repo")
	}
}

func TestNoColorFormatterAlertLinkEmptyWhenNoAlertNumber(t *testing.T) {
	ncf := &NoColorFormatter{}
	ai := &AdvisoryItem{AlertNumber: 0}
	if got := ncf.FormatAlertLink(ai); got != "" {
		t.Errorf("FormatAlertLink() = %q, want empty string", got)
	}
}

func TestColorFormatterFormatAlertLinkEmptyWhenNoAlertNumber(t *testing.T) {
	cf := &ColorFormatter{}
	ai := &AdvisoryItem{AlertNumber: 0}
	if got := cf.FormatAlertLink(ai); got != "" {
		t.Errorf("FormatAlertLink() = %q, want empty string", got)
	}
}

func TestColorFormatterFormatSeverityContainsSeverityText(t *testing.T) {
	cf := &ColorFormatter{}
	for _, severity := range []string{"CRITICAL", "HIGH", "MODERATE", "LOW", "-"} {
		ai := &AdvisoryItem{Severity: severity}
		if got := cf.FormatSeverity(ai); !strings.Contains(got, severity) {
			t.Errorf("FormatSeverity(%q) = %q, should contain %q", severity, got, severity)
		}
	}
}

func TestColorFormatterFormatIdentifier(t *testing.T) {
	cf := &ColorFormatter{}
	tests := []struct {
		alertType   string
		expectedURL string
	}{
		{"code-scanning", "https://github.com/owner/repo/security/code-scanning/1"},
		{"secret-scanning", "https://github.com/owner/repo/security/secret-scanning/1"},
		{"malware", "https://github.com/advisories/GHSA-xxxx"},
		{"dependabot", "https://github.com/advisories/GHSA-xxxx"},
	}
	for _, tt := range tests {
		ai := &AdvisoryItem{AlertType: tt.alertType, Identifier: "GHSA-xxxx", RepositoryName: "owner/repo", AlertNumber: 1}
		got := cf.FormatIdentifier(ai)
		if !strings.Contains(got, "GHSA-xxxx") {
			t.Errorf("FormatIdentifier() for alertType %q = %q, should contain Identifier", tt.alertType, got)
		}
		if !strings.Contains(got, tt.expectedURL) {
			t.Errorf("FormatIdentifier() for alertType %q = %q, should contain URL %q", tt.alertType, got, tt.expectedURL)
		}
	}
}
