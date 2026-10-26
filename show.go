package main

import (
	"fmt"

	"github.com/cli/go-gh/v2/pkg/api"
	graphql "github.com/cli/shurcooL-graphql"
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
			VulnerableVersionRange string
			FirstPatchedVersion    struct{ Identifier string }
			UpdatedAt              string
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
	variables := map[string]any{
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

	formatter := NewFormatter(opts.NoColor)
	item := &AdvisoryItem{Identifier: sanitizeLine(ghsaId), Severity: sanitizeLine(advisory.Severity)}
	fmt.Printf("GHSA ID: %s\n", formatter.FormatIdentifier(item))
	fmt.Printf("Severity: %s\n", formatter.FormatSeverity(item))
	fmt.Printf("Summary: %s\n", sanitizeLine(advisory.Summary))
	fmt.Printf("Published: %s\n", sanitizeLine(advisory.PublishedAt))
	fmt.Printf("Updated: %s\n", sanitizeLine(advisory.UpdatedAt))
	fmt.Printf("URL: %s\n", sanitizeLine(advisory.Permalink))
	fmt.Println()

	if advisory.Description != "" {
		fmt.Println("Description:")
		fmt.Println(sanitizeMultiline(advisory.Description))
		fmt.Println()
	}

	if len(advisory.Identifiers) > 0 {
		fmt.Println("Identifiers:")
		for _, id := range advisory.Identifiers {
			fmt.Printf("  %s: %s\n", sanitizeLine(id.Type), sanitizeLine(id.Value))
		}
		fmt.Println()
	}

	if len(advisory.References) > 0 {
		fmt.Println("References:")
		for _, ref := range advisory.References {
			fmt.Printf("  - %s\n", sanitizeLine(ref.Url))
		}
		fmt.Println()
	}

	if len(advisory.Vulnerabilities.Nodes) > 0 {
		fmt.Println("Affected Packages:")
		for _, vuln := range advisory.Vulnerabilities.Nodes {
			fmt.Printf("  - %s (%s)\n", sanitizeLine(vuln.Package.Name), sanitizeLine(vuln.Package.Ecosystem))
			fmt.Printf("    Vulnerable: %s\n", sanitizeLine(vuln.VulnerableVersionRange))
			if vuln.FirstPatchedVersion.Identifier != "" {
				fmt.Printf("    Patched: %s\n", sanitizeLine(vuln.FirstPatchedVersion.Identifier))
			}
		}
		fmt.Println()
	}

	return nil
}
