package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
	graphql "github.com/cli/shurcooL-graphql"
)

type SecurityAdvisory struct {
	GhsaId   string
	Summary  string
	Severity string
}

type VulnerabilityAlert struct {
	Id               string
	CreatedAt        time.Time
	SecurityAdvisory SecurityAdvisory
}

type Repository struct {
	Name  string
	Owner struct {
		Login string
	}
	VulnerabilityAlerts struct {
		Nodes []VulnerabilityAlert
	} `graphql:"vulnerabilityAlerts(first: $alertLimit, states: OPEN)"`
}

type SearchResultItemConnection struct {
	PageInfo struct {
		HasNextPage bool
		EndCursor   string
	}
	Nodes []struct {
		Repository Repository `graphql:"... on Repository"`
	}
}

type query struct {
	Search SearchResultItemConnection `graphql:"search(query: $searchQuery, type: REPOSITORY, first: 100, after: $cursor)"`
}

type RepositoryItem struct {
	Name          string
	AdvisoryItems []AdvisoryItem
}

type AdvisoryItem struct {
	GhsaId         string
	Summary        string
	Severity       string
	CreatedAt      time.Time
	RepositoryName string
}

func shouldExcludeRepository(repoFullName string, excludes *[]string) bool {
	for _, exclude := range *excludes {
		if strings.Contains(repoFullName, exclude) {
			return true
		}
	}
	return false
}

func shouldIncludeSeverity(severity string, severities *[]string) bool {
	if len(*severities) == 0 {
		return true
	}
	for _, s := range *severities {
		if strings.EqualFold(s, severity) {
			return true
		}
	}
	return false
}

func fetchSecurityAdvisories(owner string, opts *Options) ([]RepositoryItem, error) {
	client, err := api.DefaultGraphQLClient()
	if err != nil {
		return []RepositoryItem{}, err
	}

	var allRepositories []Repository
	var cursor *graphql.String
	searchQuery := fmt.Sprintf("user:%s archived:false", owner)

	for {
		var q query
		variables := map[string]interface{}{
			"searchQuery": graphql.String(searchQuery),
			"cursor":      cursor,
			"alertLimit":  graphql.Int(opts.Limit),
		}

		err = client.Query("GetSecurityAdvisories", &q, variables)
		if err != nil {
			return []RepositoryItem{}, err
		}

		for _, node := range q.Search.Nodes {
			allRepositories = append(allRepositories, node.Repository)
		}

		if !q.Search.PageInfo.HasNextPage {
			break
		}
		endCursor := graphql.String(q.Search.PageInfo.EndCursor)
		cursor = &endCursor
	}

	repoMap := map[string]RepositoryItem{}
	for _, repo := range allRepositories {
		if len(repo.VulnerabilityAlerts.Nodes) == 0 {
			continue
		}

		repoFullName := fmt.Sprintf("%s/%s", repo.Owner.Login, repo.Name)

		if shouldExcludeRepository(repoFullName, opts.Excludes) {
			continue
		}

		advisoryItems := []AdvisoryItem{}
		for _, alert := range repo.VulnerabilityAlerts.Nodes {
			if !shouldIncludeSeverity(alert.SecurityAdvisory.Severity, opts.Severities) {
				continue
			}
			advisoryItems = append(advisoryItems, AdvisoryItem{
				GhsaId:         alert.SecurityAdvisory.GhsaId,
				Summary:        alert.SecurityAdvisory.Summary,
				Severity:       alert.SecurityAdvisory.Severity,
				CreatedAt:      alert.CreatedAt,
				RepositoryName: repoFullName,
			})
		}

		if len(advisoryItems) == 0 {
			continue
		}

		repoMap[repoFullName] = RepositoryItem{
			Name:          repoFullName,
			AdvisoryItems: advisoryItems,
		}
	}

	for name := range repoMap {
		items := repoMap[name].AdvisoryItems
		sort.Slice(items, func(i, j int) bool {
			return items[j].CreatedAt.Before(items[i].CreatedAt)
		})
		repoMap[name] = RepositoryItem{
			Name:          name,
			AdvisoryItems: items,
		}
	}

	// get sorted repositories
	repoNames := make([]string, 0, len(repoMap))
	for name := range repoMap {
		repoNames = append(repoNames, name)
	}
	sort.Strings(repoNames)

	repositories := make([]RepositoryItem, 0, len(repoMap))
	for _, name := range repoNames {
		repositories = append(repositories, repoMap[name])
	}

	return repositories, nil
}
