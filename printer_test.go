package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAlertLinkRawText(t *testing.T) {
	if got := alertLinkRawText(&AdvisoryItem{AlertNumber: 0}); got != "" {
		t.Errorf("alertLinkRawText(AlertNumber=0) = %q, want empty string", got)
	}
	if got := alertLinkRawText(&AdvisoryItem{AlertNumber: 42}); got != "#42" {
		t.Errorf("alertLinkRawText(AlertNumber=42) = %q, want %q", got, "#42")
	}
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() failed: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = original }()

	f()

	w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("io.Copy() failed: %v", err)
	}
	return buf.String()
}

func TestPrintLine(t *testing.T) {
	ai := &AdvisoryItem{
		AlertType:      "dependabot",
		AlertNumber:    1,
		Identifier:     "GHSA-a",
		Summary:        "summary",
		Severity:       "HIGH",
		CreatedAt:      time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		RepositoryName: "owner/repo",
	}
	formatter := &NoColorFormatter{}

	// Widths equal to each field's own length so padding is zero, keeping the
	// expected output simple to compute by hand.
	out := captureStdout(t, func() {
		ai.printLine(len(ai.AlertType), len(alertLinkRawText(ai)), len(ai.Identifier), len(ai.Severity), formatter)
	})

	want := "dependabot  #1  GHSA-a  HIGH  2026-01-02 summary\n"
	if out != want {
		t.Errorf("printLine() output = %q, want %q", out, want)
	}
}

func TestPrintList(t *testing.T) {
	ri := &RepositoryItem{
		Name: "owner/repo",
		AdvisoryItems: []AdvisoryItem{
			{
				AlertType:      "code-scanning",
				AlertNumber:    1,
				Identifier:     "GHSA-a",
				Summary:        "short one",
				Severity:       "HIGH",
				CreatedAt:      time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
				RepositoryName: "owner/repo",
			},
			{
				AlertType:      "dependabot",
				AlertNumber:    123,
				Identifier:     "GHSA-longer-id",
				Summary:        "another one",
				Severity:       "MODERATE",
				CreatedAt:      time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC),
				RepositoryName: "owner/repo",
			},
		},
	}
	opts := &Options{NoColor: true}

	out := captureStdout(t, func() {
		ri.printList(opts)
	})

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("printList() produced %d lines, want 3: %q", len(lines), out)
	}
	if lines[0] != "# owner/repo" {
		t.Errorf("header line = %q, want %q", lines[0], "# owner/repo")
	}

	// Columns must line up: the alert type column is padded to the width of
	// the longest AlertType ("code-scanning"), so every row's GHSA-ID column
	// must start at the same byte offset.
	firstGhsaIdx := strings.Index(lines[1], "GHSA-a")
	secondGhsaIdx := strings.Index(lines[2], "GHSA-longer-id")
	if firstGhsaIdx != secondGhsaIdx {
		t.Errorf("GHSA ID column not aligned: line1 idx=%d, line2 idx=%d\nline1=%q\nline2=%q", firstGhsaIdx, secondGhsaIdx, lines[1], lines[2])
	}
}
