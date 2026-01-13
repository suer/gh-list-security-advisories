package main

import (
	"fmt"

	"github.com/cli/go-gh/v2/pkg/api"
	graphql "github.com/cli/shurcooL-graphql"
	"github.com/logrusorgru/aurora/v4"
)

type SecurityAdvisoryDetail struct {
	GhsaId      string
	Summary     string
	Description string
	Severity    string
	PublishedAt string
	UpdatedAt   string
	Permalink   string
	Identifiers []struct {
		Type  string
		Value string
	}
	References []struct {
		Url string
	}
	Vulnerabilities struct {
		Nodes []struct {
			Package struct {
				Name      string
				Ecosystem string
			}
			VulnerableVersionRange   string
			FirstPatchedVersion      struct{ Identifier string }
			UpdatedAt                string
		}
	} `graphql:"vulnerabilities(first: 10)"`
}

type advisoryQuery struct {
	SecurityAdvisory SecurityAdvisoryDetail `graphql:"securityAdvisory(ghsaId: $ghsaId)"`
}

func fetchAdvisoryDetail(ghsaId string) (*SecurityAdvisoryDetail, error) {
	client, err := api.DefaultGraphQLClient()
	if err != nil {
		return nil, err
	}

	var q advisoryQuery
	variables := map[string]interface{}{
		"ghsaId": graphql.String(ghsaId),
	}

	err = client.Query("GetAdvisoryDetail", &q, variables)
	if err != nil {
		return nil, err
	}

	return &q.SecurityAdvisory, nil
}

func showAdvisory(ghsaId string, opts *Options) error {
	advisory, err := fetchAdvisoryDetail(ghsaId)
	if err != nil {
		return err
	}

	fmt.Printf("GHSA ID: %s\n", formatGhsaIdForShow(ghsaId, opts.NoColor))
	fmt.Printf("Severity: %s\n", formatSeverityForShow(advisory.Severity, opts.NoColor))
	fmt.Printf("Summary: %s\n", advisory.Summary)
	fmt.Printf("Published: %s\n", advisory.PublishedAt)
	fmt.Printf("Updated: %s\n", advisory.UpdatedAt)
	fmt.Printf("URL: %s\n", advisory.Permalink)
	fmt.Println()

	if advisory.Description != "" {
		fmt.Println("Description:")
		fmt.Println(advisory.Description)
		fmt.Println()
	}

	if len(advisory.Identifiers) > 0 {
		fmt.Println("Identifiers:")
		for _, id := range advisory.Identifiers {
			fmt.Printf("  %s: %s\n", id.Type, id.Value)
		}
		fmt.Println()
	}

	if len(advisory.References) > 0 {
		fmt.Println("References:")
		for _, ref := range advisory.References {
			fmt.Printf("  - %s\n", ref.Url)
		}
		fmt.Println()
	}

	if len(advisory.Vulnerabilities.Nodes) > 0 {
		fmt.Println("Affected Packages:")
		for _, vuln := range advisory.Vulnerabilities.Nodes {
			fmt.Printf("  - %s (%s)\n", vuln.Package.Name, vuln.Package.Ecosystem)
			fmt.Printf("    Vulnerable: %s\n", vuln.VulnerableVersionRange)
			if vuln.FirstPatchedVersion.Identifier != "" {
				fmt.Printf("    Patched: %s\n", vuln.FirstPatchedVersion.Identifier)
			}
		}
		fmt.Println()
	}

	return nil
}

func formatGhsaIdForShow(ghsaId string, noColor bool) string {
	if noColor {
		return ghsaId
	}
	url := fmt.Sprintf("https://github.com/advisories/%s", ghsaId)
	return aurora.Cyan(ghsaId).Hyperlink(url).String()
}

func formatSeverityForShow(severity string, noColor bool) string {
	if noColor {
		return severity
	}
	switch severity {
	case "CRITICAL":
		return aurora.Red(severity).Bold().String()
	case "HIGH":
		return aurora.Red(severity).String()
	case "MODERATE":
		return aurora.Yellow(severity).String()
	case "LOW":
		return aurora.Green(severity).String()
	default:
		return severity
	}
}
