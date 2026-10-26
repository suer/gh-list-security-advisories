package main

import "testing"

func TestSanitizeText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		fn   func(string) string
		want string
	}{
		{"plain", "hello world", sanitizeLine, "hello world"},
		{"escape sequence", "a\x1b]52;c;Zm9v\x07b", sanitizeLine, "a ]52;c;Zm9v b"},
		{"newline stripped in line", "a\nb\tc", sanitizeLine, "a b c"},
		{"newline kept in multiline", "a\nb\tc", sanitizeMultiline, "a\nb\tc"},
		{"escape stripped in multiline", "a\x1b[31mb", sanitizeMultiline, "a [31mb"},
		{"C1 control", "a\u009bb", sanitizeLine, "a b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fn(tt.in); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAddToRepoMapSanitizes(t *testing.T) {
	m := map[string]RepositoryItem{}
	addToRepoMap(m, AdvisoryItem{RepositoryName: "o/r", Identifier: "GHSA\x1b[2J", Severity: "HIGH", Summary: "x\x1b]0;t\x07"})
	got := m["o/r"].AdvisoryItems[0]
	if got.Identifier != "GHSA [2J" || got.Summary != "x ]0;t " {
		t.Errorf("not sanitized: %+v", got)
	}
}
