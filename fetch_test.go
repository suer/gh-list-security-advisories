package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
)

func TestShouldExcludeRepository(t *testing.T) {
	tests := []struct {
		name         string
		repoFullName string
		excludes     []string
		want         bool
	}{
		{"no excludes", "owner/repo", []string{}, false},
		{"exact match", "owner/repo", []string{"owner/repo"}, true},
		{"partial match on repo name", "owner/repo", []string{"repo"}, true},
		{"partial match on owner name", "owner/repo", []string{"owner"}, true},
		{"no match", "owner/repo", []string{"other"}, false},
		{"match among multiple", "owner/repo", []string{"other", "repo"}, true},
		{"empty string exclude matches everything", "owner/repo", []string{""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldExcludeRepository(tt.repoFullName, tt.excludes); got != tt.want {
				t.Errorf("shouldExcludeRepository(%q, %v) = %v, want %v", tt.repoFullName, tt.excludes, got, tt.want)
			}
		})
	}
}

func TestShouldIncludeSeverity(t *testing.T) {
	tests := []struct {
		name       string
		severity   string
		severities []string
		want       bool
	}{
		{"no filter includes everything", "HIGH", []string{}, true},
		{"exact match", "HIGH", []string{"HIGH"}, true},
		{"case insensitive match", "high", []string{"HIGH"}, true},
		{"no match", "LOW", []string{"HIGH"}, false},
		{"match among multiple", "MODERATE", []string{"HIGH", "MODERATE"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldIncludeSeverity(tt.severity, tt.severities); got != tt.want {
				t.Errorf("shouldIncludeSeverity(%q, %v) = %v, want %v", tt.severity, tt.severities, got, tt.want)
			}
		})
	}
}

func TestMapCodeScanningSeverity(t *testing.T) {
	tests := []struct {
		name     string
		secLevel string
		severity string
		want     string
	}{
		{"security severity level takes precedence", "critical", "note", "CRITICAL"},
		{"high security severity level", "high", "", "HIGH"},
		{"medium security severity level maps to moderate", "medium", "", "MODERATE"},
		{"low security severity level", "low", "", "LOW"},
		{"security severity level is case insensitive", "CRITICAL", "", "CRITICAL"},
		{"falls back to severity error", "", "error", "HIGH"},
		{"falls back to severity warning", "", "warning", "MODERATE"},
		{"falls back to severity note", "", "note", "LOW"},
		{"severity fallback is case insensitive", "", "ERROR", "HIGH"},
		{"unknown values default to low", "", "", "LOW"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapCodeScanningSeverity(tt.secLevel, tt.severity); got != tt.want {
				t.Errorf("mapCodeScanningSeverity(%q, %q) = %q, want %q", tt.secLevel, tt.severity, got, tt.want)
			}
		})
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"404 http error", &api.HTTPError{StatusCode: 404}, true},
		{"other http error", &api.HTTPError{StatusCode: 500}, false},
		{"non http error", errors.New("boom"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNotFound(tt.err); got != tt.want {
				t.Errorf("isNotFound(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestAddToRepoMap(t *testing.T) {
	repoMap := map[string]RepositoryItem{}

	addToRepoMap(repoMap, AdvisoryItem{RepositoryName: "owner/repo", Identifier: "GHSA-1"})
	addToRepoMap(repoMap, AdvisoryItem{RepositoryName: "owner/repo", Identifier: "GHSA-2"})

	ri, ok := repoMap["owner/repo"]
	if !ok {
		t.Fatalf("expected repoMap to contain %q", "owner/repo")
	}
	if ri.Name != "owner/repo" {
		t.Errorf("ri.Name = %q, want %q", ri.Name, "owner/repo")
	}
	if len(ri.AdvisoryItems) != 2 {
		t.Fatalf("len(ri.AdvisoryItems) = %d, want 2", len(ri.AdvisoryItems))
	}
	if ri.AdvisoryItems[0].Identifier != "GHSA-1" || ri.AdvisoryItems[1].Identifier != "GHSA-2" {
		t.Errorf("unexpected AdvisoryItems order: %+v", ri.AdvisoryItems)
	}
}

func TestCollectCodeScanningAlert(t *testing.T) {
	baseAlert := codeScanningAlertResponse{
		Number:    42,
		CreatedAt: "2026-01-02T15:04:05Z",
	}
	baseAlert.Rule.ID = "rule-id"
	baseAlert.Rule.Description = "some description"
	baseAlert.Rule.SecuritySeverityLevel = "high"

	t.Run("included alert is mapped", func(t *testing.T) {
		opts := &Options{Excludes: []string{}, Severities: []string{}}
		item, ok, err := collectCodeScanningAlert(baseAlert, "owner/repo", opts)
		if !ok {
			t.Fatalf("expected alert to be included")
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := AdvisoryItem{
			AlertType:      "code-scanning",
			AlertNumber:    42,
			Identifier:     "rule-id",
			Summary:        "some description",
			Severity:       "HIGH",
			CreatedAt:      time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC),
			RepositoryName: "owner/repo",
		}
		if item != want {
			t.Errorf("collectCodeScanningAlert() = %+v, want %+v", item, want)
		}
	})

	t.Run("excluded repository is dropped", func(t *testing.T) {
		opts := &Options{Excludes: []string{"owner/repo"}, Severities: []string{}}
		if _, ok, _ := collectCodeScanningAlert(baseAlert, "owner/repo", opts); ok {
			t.Errorf("expected alert to be excluded")
		}
	})

	t.Run("filtered severity is dropped", func(t *testing.T) {
		opts := &Options{Excludes: []string{}, Severities: []string{"LOW"}}
		if _, ok, _ := collectCodeScanningAlert(baseAlert, "owner/repo", opts); ok {
			t.Errorf("expected alert to be filtered out by severity")
		}
	})

	t.Run("invalid created_at is reported as an error but the alert is kept", func(t *testing.T) {
		opts := &Options{Excludes: []string{}, Severities: []string{}}
		alert := baseAlert
		alert.CreatedAt = "not-a-time"
		item, ok, err := collectCodeScanningAlert(alert, "owner/repo", opts)
		if !ok {
			t.Fatalf("expected alert to be included")
		}
		if err == nil {
			t.Fatalf("expected an error for an unparsable created_at")
		}
		if !item.CreatedAt.IsZero() {
			t.Errorf("CreatedAt = %v, want zero value", item.CreatedAt)
		}
	})
}

func TestCollectSecretScanningAlert(t *testing.T) {
	baseAlert := secretScanningAlertResponse{
		Number:                7,
		CreatedAt:             "2026-03-04T00:00:00Z",
		SecretType:            "aws_key",
		SecretTypeDisplayName: "AWS Key",
	}

	t.Run("included alert is mapped", func(t *testing.T) {
		opts := &Options{Excludes: []string{}, Severities: []string{}}
		item, ok, err := collectSecretScanningAlert(baseAlert, "owner/repo", opts)
		if !ok {
			t.Fatalf("expected alert to be included")
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := AdvisoryItem{
			AlertType:      "secret-scanning",
			AlertNumber:    7,
			Identifier:     "aws_key",
			Summary:        "AWS Key",
			Severity:       "-",
			CreatedAt:      time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC),
			RepositoryName: "owner/repo",
		}
		if item != want {
			t.Errorf("collectSecretScanningAlert() = %+v, want %+v", item, want)
		}
	})

	t.Run("falls back to secret type when display name is empty", func(t *testing.T) {
		opts := &Options{Excludes: []string{}, Severities: []string{}}
		alert := baseAlert
		alert.SecretTypeDisplayName = ""
		item, ok, err := collectSecretScanningAlert(alert, "owner/repo", opts)
		if !ok {
			t.Fatalf("expected alert to be included")
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if item.Summary != "aws_key" {
			t.Errorf("Summary = %q, want %q", item.Summary, "aws_key")
		}
	})

	t.Run("excluded repository is dropped", func(t *testing.T) {
		opts := &Options{Excludes: []string{"owner/repo"}, Severities: []string{}}
		if _, ok, _ := collectSecretScanningAlert(baseAlert, "owner/repo", opts); ok {
			t.Errorf("expected alert to be excluded")
		}
	})

	t.Run("invalid created_at is reported as an error but the alert is kept", func(t *testing.T) {
		opts := &Options{Excludes: []string{}, Severities: []string{}}
		alert := baseAlert
		alert.CreatedAt = "not-a-time"
		item, ok, err := collectSecretScanningAlert(alert, "owner/repo", opts)
		if !ok {
			t.Fatalf("expected alert to be included")
		}
		if err == nil {
			t.Fatalf("expected an error for an unparsable created_at")
		}
		if !item.CreatedAt.IsZero() {
			t.Errorf("CreatedAt = %v, want zero value", item.CreatedAt)
		}
	})
}

func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	original := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() failed: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = original }()

	f()

	w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("io.Copy() failed: %v", err)
	}
	return buf.String()
}

func TestWarnIfVerbose(t *testing.T) {
	t.Run("nil error prints nothing even when verbose", func(t *testing.T) {
		out := captureStderr(t, func() {
			warnIfVerbose(&Options{Verbose: true}, nil)
		})
		if out != "" {
			t.Errorf("warnIfVerbose(verbose, nil) printed %q, want nothing", out)
		}
	})

	t.Run("error is silenced when not verbose", func(t *testing.T) {
		out := captureStderr(t, func() {
			warnIfVerbose(&Options{Verbose: false}, errors.New("boom"))
		})
		if out != "" {
			t.Errorf("warnIfVerbose(non-verbose, err) printed %q, want nothing", out)
		}
	})

	t.Run("error is printed to stderr when verbose", func(t *testing.T) {
		out := captureStderr(t, func() {
			warnIfVerbose(&Options{Verbose: true}, errors.New("boom"))
		})
		if !strings.Contains(out, "boom") {
			t.Errorf("warnIfVerbose(verbose, err) printed %q, want it to contain %q", out, "boom")
		}
	})
}
