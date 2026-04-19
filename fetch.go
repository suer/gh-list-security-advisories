package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
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
	AlertType      string
	AlertNumber    int
	GhsaId         string
	Summary        string
	Severity       string
	CreatedAt      time.Time
	RepositoryName string
}

type codeScanningAlertResponse struct {
	Number    int    `json:"number"`
	CreatedAt string `json:"created_at"`
	Rule      struct {
		ID                    string `json:"id"`
		Description           string `json:"description"`
		SecuritySeverityLevel string `json:"security_severity_level"`
		Severity              string `json:"severity"`
	} `json:"rule"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

type secretScanningAlertResponse struct {
	Number                int    `json:"number"`
	CreatedAt             string `json:"created_at"`
	SecretType            string `json:"secret_type"`
	SecretTypeDisplayName string `json:"secret_type_display_name"`
	Repository            struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
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

func mapCodeScanningSeverity(secLevel, severity string) string {
	switch strings.ToLower(secLevel) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium":
		return "MODERATE"
	case "low":
		return "LOW"
	}
	switch strings.ToLower(severity) {
	case "error":
		return "HIGH"
	case "warning":
		return "MODERATE"
	case "note":
		return "LOW"
	}
	return "LOW"
}

func isNotFound(err error) bool {
	var httpErr *api.HTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == 404
}

func addToRepoMap(repoMap map[string]RepositoryItem, item AdvisoryItem) {
	ri := repoMap[item.RepositoryName]
	ri.Name = item.RepositoryName
	ri.AdvisoryItems = append(ri.AdvisoryItems, item)
	repoMap[item.RepositoryName] = ri
}

// fetchDependabotAlerts fetches vulnerability alerts via GraphQL and returns all repo full names found.
func fetchDependabotAlerts(gqlClient *api.GraphQLClient, owner string, opts *Options, repoMap map[string]RepositoryItem) ([]string, error) {
	var cursor *graphql.String
	searchQuery := fmt.Sprintf("user:%s archived:false", owner)
	var allRepoNames []string

	for {
		var q query
		variables := map[string]interface{}{
			"searchQuery": graphql.String(searchQuery),
			"cursor":      cursor,
			"alertLimit":  graphql.Int(opts.Limit),
		}

		if err := gqlClient.Query("GetSecurityAdvisories", &q, variables); err != nil {
			return nil, err
		}

		for _, node := range q.Search.Nodes {
			repo := node.Repository
			repoFullName := fmt.Sprintf("%s/%s", repo.Owner.Login, repo.Name)
			allRepoNames = append(allRepoNames, repoFullName)

			if shouldExcludeRepository(repoFullName, opts.Excludes) {
				continue
			}
			for _, alert := range repo.VulnerabilityAlerts.Nodes {
				if !shouldIncludeSeverity(alert.SecurityAdvisory.Severity, opts.Severities) {
					continue
				}
				addToRepoMap(repoMap, AdvisoryItem{
					AlertType:      "dependabot",
					GhsaId:         alert.SecurityAdvisory.GhsaId,
					Summary:        alert.SecurityAdvisory.Summary,
					Severity:       alert.SecurityAdvisory.Severity,
					CreatedAt:      alert.CreatedAt,
					RepositoryName: repoFullName,
				})
			}
		}

		if !q.Search.PageInfo.HasNextPage {
			break
		}
		endCursor := graphql.String(q.Search.PageInfo.EndCursor)
		cursor = &endCursor
	}
	return allRepoNames, nil
}

func collectCodeScanningAlert(alert codeScanningAlertResponse, repoFullName string, opts *Options) (AdvisoryItem, bool) {
	severity := mapCodeScanningSeverity(alert.Rule.SecuritySeverityLevel, alert.Rule.Severity)
	if shouldExcludeRepository(repoFullName, opts.Excludes) {
		return AdvisoryItem{}, false
	}
	if !shouldIncludeSeverity(severity, opts.Severities) {
		return AdvisoryItem{}, false
	}
	createdAt, _ := time.Parse(time.RFC3339, alert.CreatedAt)
	return AdvisoryItem{
		AlertType:      "code-scanning",
		AlertNumber:    alert.Number,
		GhsaId:         alert.Rule.ID,
		Summary:        alert.Rule.Description,
		Severity:       severity,
		CreatedAt:      createdAt,
		RepositoryName: repoFullName,
	}, true
}

func fetchCodeScanningAlertsOrg(restClient *api.RESTClient, org string, opts *Options, repoMap map[string]RepositoryItem) bool {
	for page := 1; ; page++ {
		path := fmt.Sprintf("orgs/%s/code-scanning/alerts?state=open&per_page=100&page=%d", org, page)
		var alerts []codeScanningAlertResponse
		if err := restClient.Get(path, &alerts); err != nil {
			if isNotFound(err) {
				return false
			}
			break
		}
		if len(alerts) == 0 {
			break
		}
		for _, alert := range alerts {
			if item, ok := collectCodeScanningAlert(alert, alert.Repository.FullName, opts); ok {
				addToRepoMap(repoMap, item)
			}
		}
	}
	return true
}

func collectCodeScanningAlertsForRepo(restClient *api.RESTClient, repoFullName string, opts *Options) []AdvisoryItem {
	var items []AdvisoryItem
	for page := 1; ; page++ {
		path := fmt.Sprintf("repos/%s/code-scanning/alerts?state=open&per_page=100&page=%d", repoFullName, page)
		var alerts []codeScanningAlertResponse
		if err := restClient.Get(path, &alerts); err != nil {
			break
		}
		if len(alerts) == 0 {
			break
		}
		for _, alert := range alerts {
			if item, ok := collectCodeScanningAlert(alert, repoFullName, opts); ok {
				items = append(items, item)
			}
		}
	}
	return items
}

func fetchCodeScanningAlerts(restClient *api.RESTClient, owner string, allRepos []string, opts *Options, repoMap map[string]RepositoryItem, pb *ProgressBar) {
	if fetchCodeScanningAlertsOrg(restClient, owner, opts, repoMap) {
		pb.current.Add(int64(len(allRepos)))
		return
	}
	const concurrency = 10
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, repo := range allRepos {
		wg.Add(1)
		sem <- struct{}{}
		go func(repoFullName string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer pb.Increment()
			items := collectCodeScanningAlertsForRepo(restClient, repoFullName, opts)
			if len(items) > 0 {
				mu.Lock()
				for _, item := range items {
					addToRepoMap(repoMap, item)
				}
				mu.Unlock()
			}
		}(repo)
	}
	wg.Wait()
}

func collectSecretScanningAlert(alert secretScanningAlertResponse, repoFullName string, opts *Options) (AdvisoryItem, bool) {
	if shouldExcludeRepository(repoFullName, opts.Excludes) {
		return AdvisoryItem{}, false
	}
	displayName := alert.SecretTypeDisplayName
	if displayName == "" {
		displayName = alert.SecretType
	}
	createdAt, _ := time.Parse(time.RFC3339, alert.CreatedAt)
	return AdvisoryItem{
		AlertType:      "secret-scanning",
		AlertNumber:    alert.Number,
		GhsaId:         alert.SecretType,
		Summary:        displayName,
		Severity:       "-",
		CreatedAt:      createdAt,
		RepositoryName: repoFullName,
	}, true
}

func fetchSecretScanningAlertsOrg(restClient *api.RESTClient, org string, opts *Options, repoMap map[string]RepositoryItem) bool {
	for page := 1; ; page++ {
		path := fmt.Sprintf("orgs/%s/secret-scanning/alerts?state=open&per_page=100&page=%d", org, page)
		var alerts []secretScanningAlertResponse
		if err := restClient.Get(path, &alerts); err != nil {
			if isNotFound(err) {
				return false
			}
			break
		}
		if len(alerts) == 0 {
			break
		}
		for _, alert := range alerts {
			if item, ok := collectSecretScanningAlert(alert, alert.Repository.FullName, opts); ok {
				addToRepoMap(repoMap, item)
			}
		}
	}
	return true
}

func collectSecretScanningAlertsForRepo(restClient *api.RESTClient, repoFullName string, opts *Options) []AdvisoryItem {
	var items []AdvisoryItem
	for page := 1; ; page++ {
		path := fmt.Sprintf("repos/%s/secret-scanning/alerts?state=open&per_page=100&page=%d", repoFullName, page)
		var alerts []secretScanningAlertResponse
		if err := restClient.Get(path, &alerts); err != nil {
			break
		}
		if len(alerts) == 0 {
			break
		}
		for _, alert := range alerts {
			if item, ok := collectSecretScanningAlert(alert, repoFullName, opts); ok {
				items = append(items, item)
			}
		}
	}
	return items
}

func fetchSecretScanningAlerts(restClient *api.RESTClient, owner string, allRepos []string, opts *Options, repoMap map[string]RepositoryItem, pb *ProgressBar) {
	// Secret scanning alerts have no severity; skip when severity filter is active
	if len(*opts.Severities) > 0 {
		pb.current.Add(int64(len(allRepos)))
		return
	}
	if fetchSecretScanningAlertsOrg(restClient, owner, opts, repoMap) {
		pb.current.Add(int64(len(allRepos)))
		return
	}
	const concurrency = 10
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, repo := range allRepos {
		wg.Add(1)
		sem <- struct{}{}
		go func(repoFullName string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer pb.Increment()
			items := collectSecretScanningAlertsForRepo(restClient, repoFullName, opts)
			if len(items) > 0 {
				mu.Lock()
				for _, item := range items {
					addToRepoMap(repoMap, item)
				}
				mu.Unlock()
			}
		}(repo)
	}
	wg.Wait()
}

func fetchSecurityAdvisories(owner string, opts *Options, pb *ProgressBar) ([]RepositoryItem, error) {
	gqlClient, err := api.DefaultGraphQLClient()
	if err != nil {
		return nil, err
	}
	restClient, err := api.DefaultRESTClient()
	if err != nil {
		return nil, err
	}

	repoMap := map[string]RepositoryItem{}

	allRepos, err := fetchDependabotAlerts(gqlClient, owner, opts, repoMap)
	if err != nil {
		return nil, err
	}
	pb.AddTotal(len(allRepos) * 2)
	fetchCodeScanningAlerts(restClient, owner, allRepos, opts, repoMap, pb)
	fetchSecretScanningAlerts(restClient, owner, allRepos, opts, repoMap, pb)

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
