package main

import (
	"strings"
	"unicode"
)

func sanitizeText(s string, keepWhitespace bool) string {
	return strings.Map(func(r rune) rune {
		if keepWhitespace && (r == '\n' || r == '\t') {
			return r
		}
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

func sanitizeLine(s string) string {
	return sanitizeText(s, false)
}

func sanitizeMultiline(s string) string {
	return sanitizeText(s, true)
}
