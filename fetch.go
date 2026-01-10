package main

import (
	"fmt"
	"sort"
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
	Name                string
	VulnerabilityAlerts struct {
		Nodes []VulnerabilityAlert
	} `graphql:"vulnerabilityAlerts(first: 100, states: OPEN)"`
}

type RepositoryConnection struct {
	PageInfo struct {
		HasNextPage bool
		EndCursor   string
	}
	Nodes []Repository
}

type query struct {
	RepositoryOwner struct {
		Repositories RepositoryConnection `graphql:"repositories(first: 100, after: $cursor)"`
	} `graphql:"repositoryOwner(login: $owner)"`
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

func fetchSecurityAdvisories(owner string) ([]RepositoryItem, error) {
	client, err := api.DefaultGraphQLClient()
	if err != nil {
		return []RepositoryItem{}, err
	}

	var allRepositories []Repository
	var cursor *graphql.String

	for {
		var q query
		variables := map[string]interface{}{
			"owner":  graphql.String(owner),
			"cursor": cursor,
		}

		err = client.Query("GetSecurityAdvisories", &q, variables)
		if err != nil {
			return []RepositoryItem{}, err
		}

		allRepositories = append(allRepositories, q.RepositoryOwner.Repositories.Nodes...)

		if !q.RepositoryOwner.Repositories.PageInfo.HasNextPage {
			break
		}
		endCursor := graphql.String(q.RepositoryOwner.Repositories.PageInfo.EndCursor)
		cursor = &endCursor
	}

	repoMap := map[string]RepositoryItem{}
	for _, repo := range allRepositories {
		if len(repo.VulnerabilityAlerts.Nodes) == 0 {
			continue
		}

		repoFullName := fmt.Sprintf("%s/%s", owner, repo.Name)

		advisoryItems := []AdvisoryItem{}
		for _, alert := range repo.VulnerabilityAlerts.Nodes {
			advisoryItems = append(advisoryItems, AdvisoryItem{
				GhsaId:         alert.SecurityAdvisory.GhsaId,
				Summary:        alert.SecurityAdvisory.Summary,
				Severity:       alert.SecurityAdvisory.Severity,
				CreatedAt:      alert.CreatedAt,
				RepositoryName: repoFullName,
			})
		}

		repoMap[repoFullName] = RepositoryItem{
			Name:          repoFullName,
			AdvisoryItems: advisoryItems,
		}
	}

	// sort advisories in each repository by CreatedAt
	for name := range repoMap {
		items := repoMap[name].AdvisoryItems
		sort.Slice(items, func(i, j int) bool {
			return items[i].CreatedAt.Before(items[j].CreatedAt)
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
