package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
	graphql "github.com/cli/shurcooL-graphql"
)

type SecurityAdvisory struct {
	GhsaId         string
	Summary        string
	Severity       string
	Classification string
}

type VulnerabilityAlert struct {
	Number           int
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

const (
	AlertTypeDependabot     = "dependabot"
	AlertTypeMalware        = "malware"
	AlertTypeCodeScanning   = "code-scanning"
	AlertTypeSecretScanning = "secret-scanning"
)

type RepositoryItem struct {
	Name          string
	AdvisoryItems []AdvisoryItem
}

type AdvisoryItem struct {
	AlertType      string
	AlertNumber    int
	Identifier     string
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

func shouldExcludeRepository(repoFullName string, excludes []string) bool {
	for _, exclude := range excludes {
		if strings.Contains(repoFullName, exclude) {
			return true
		}
	}
	return false
}

func shouldIncludeSeverity(severity string, severities []string) bool {
	if len(severities) == 0 {
		return true
	}
	for _, s := range severities {
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
				alertType := AlertTypeDependabot
				if strings.EqualFold(alert.SecurityAdvisory.Classification, "MALWARE") {
					alertType = AlertTypeMalware
				}
				addToRepoMap(repoMap, AdvisoryItem{
					AlertType:      alertType,
					AlertNumber:    alert.Number,
					Identifier:     alert.SecurityAdvisory.GhsaId,
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

// collectCodeScanningAlert reports created-at parse failures as an error
// rather than silently falling back to the zero time, but still returns the
// item (ok=true) so a single unparsable timestamp doesn't drop the alert
// entirely; callers are expected to surface the error alongside the item.
func collectCodeScanningAlert(alert codeScanningAlertResponse, repoFullName string, opts *Options) (AdvisoryItem, bool, error) {
	severity := mapCodeScanningSeverity(alert.Rule.SecuritySeverityLevel, alert.Rule.Severity)
	if shouldExcludeRepository(repoFullName, opts.Excludes) {
		return AdvisoryItem{}, false, nil
	}
	if !shouldIncludeSeverity(severity, opts.Severities) {
		return AdvisoryItem{}, false, nil
	}
	createdAt, err := time.Parse(time.RFC3339, alert.CreatedAt)
	if err != nil {
		err = fmt.Errorf("parsing created_at %q for code-scanning alert #%d in %s: %w", alert.CreatedAt, alert.Number, repoFullName, err)
	}
	return AdvisoryItem{
		AlertType:      AlertTypeCodeScanning,
		AlertNumber:    alert.Number,
		Identifier:     alert.Rule.ID,
		Summary:        alert.Rule.Description,
		Severity:       severity,
		CreatedAt:      createdAt,
		RepositoryName: repoFullName,
	}, true, err
}

// collectSecretScanningAlert reports created-at parse failures as an error
// rather than silently falling back to the zero time, but still returns the
// item (ok=true) so a single unparsable timestamp doesn't drop the alert
// entirely; callers are expected to surface the error alongside the item.
func collectSecretScanningAlert(alert secretScanningAlertResponse, repoFullName string, opts *Options) (AdvisoryItem, bool, error) {
	if shouldExcludeRepository(repoFullName, opts.Excludes) {
		return AdvisoryItem{}, false, nil
	}
	displayName := alert.SecretTypeDisplayName
	if displayName == "" {
		displayName = alert.SecretType
	}
	createdAt, err := time.Parse(time.RFC3339, alert.CreatedAt)
	if err != nil {
		err = fmt.Errorf("parsing created_at %q for secret-scanning alert #%d in %s: %w", alert.CreatedAt, alert.Number, repoFullName, err)
	}
	return AdvisoryItem{
		AlertType:      AlertTypeSecretScanning,
		AlertNumber:    alert.Number,
		Identifier:     alert.SecretType,
		Summary:        displayName,
		Severity:       "-",
		CreatedAt:      createdAt,
		RepositoryName: repoFullName,
	}, true, err
}

// fetchAlertsOrgPaginated fetches paginated alerts from an org-level REST
// endpoint (urlPathFmt must contain exactly one %d for the page number),
// decoding each page into []T and running collect on every item. It reports
// (false, nil) when the endpoint itself is unavailable (404), signalling the
// caller to fall back to per-repo fetches; any other HTTP error, or an error
// returned by collect (e.g. a created-at parse failure), is accumulated and
// returned instead of being dropped.
func fetchAlertsOrgPaginated[T any](restClient *api.RESTClient, urlPathFmt, description string, repoMap map[string]RepositoryItem, collect func(alert T) (AdvisoryItem, bool, error)) (bool, error) {
	var errs []error
	for page := 1; ; page++ {
		path := fmt.Sprintf(urlPathFmt, page)
		var alerts []T
		if err := restClient.Get(path, &alerts); err != nil {
			if isNotFound(err) {
				return false, nil
			}
			return false, fmt.Errorf("fetching %s (page %d): %w", description, page, err)
		}
		if len(alerts) == 0 {
			break
		}
		for _, alert := range alerts {
			item, ok, err := collect(alert)
			if err != nil {
				errs = append(errs, err)
			}
			if ok {
				addToRepoMap(repoMap, item)
			}
		}
	}
	return true, errors.Join(errs...)
}

// fetchAlertsForRepoPaginated is the per-repository counterpart of
// fetchAlertsOrgPaginated (urlPathFmt must contain exactly one %d for the
// page number): a 404 simply means this repo doesn't have the feature
// enabled, but any other error is returned alongside whatever items were
// already collected, since a mid-pagination failure shouldn't discard
// alerts fetched from earlier pages.
func fetchAlertsForRepoPaginated[T any](restClient *api.RESTClient, urlPathFmt, description string, collect func(alert T) (AdvisoryItem, bool, error)) ([]AdvisoryItem, error) {
	var items []AdvisoryItem
	var errs []error
	for page := 1; ; page++ {
		path := fmt.Sprintf(urlPathFmt, page)
		var alerts []T
		if err := restClient.Get(path, &alerts); err != nil {
			if isNotFound(err) {
				break
			}
			return items, fmt.Errorf("fetching %s (page %d): %w", description, page, err)
		}
		if len(alerts) == 0 {
			break
		}
		for _, alert := range alerts {
			item, ok, err := collect(alert)
			if err != nil {
				errs = append(errs, err)
			}
			if ok {
				items = append(items, item)
			}
		}
	}
	return items, errors.Join(errs...)
}

func warnIfVerbose(opts *Options, err error) {
	if err != nil && opts.Verbose {
		fmt.Fprintf(os.Stderr, "warning: %s\n", err)
	}
}

// fetchAlertsWithFallback tries the org-level endpoint first via fetchOrg
// and only pays for a per-repo concurrent sweep via fetchForRepo when the
// org endpoint isn't available (e.g. non-Enterprise orgs, or personal
// accounts, don't expose it).
func fetchAlertsWithFallback(
	restClient *api.RESTClient,
	owner string,
	allRepos []string,
	opts *Options,
	repoMap map[string]RepositoryItem,
	pb *ProgressBar,
	fetchOrg func(restClient *api.RESTClient, org string, opts *Options, repoMap map[string]RepositoryItem) (bool, error),
	fetchForRepo func(restClient *api.RESTClient, repoFullName string, opts *Options) ([]AdvisoryItem, error),
) error {
	orgHandled, err := fetchOrg(restClient, owner, opts, repoMap)
	warnIfVerbose(opts, err)
	if orgHandled {
		pb.IncrementBy(len(allRepos))
		return err
	}
	const concurrency = 10
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	errs := []error{err}
	for _, repo := range allRepos {
		wg.Add(1)
		sem <- struct{}{}
		go func(repoFullName string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer pb.Increment()
			items, err := fetchForRepo(restClient, repoFullName, opts)
			warnIfVerbose(opts, err)
			mu.Lock()
			defer mu.Unlock()
			errs = append(errs, err)
			for _, item := range items {
				addToRepoMap(repoMap, item)
			}
		}(repo)
	}
	wg.Wait()
	return errors.Join(errs...)
}

// fetchCodeScanningAlertsOrg reports (false, nil) when the org-level endpoint
// is unavailable (404), signalling the caller to fall back to per-repo
// fetches. Any other error is returned so the caller can surface it instead
// of silently under-reporting alerts.
func fetchCodeScanningAlertsOrg(restClient *api.RESTClient, org string, opts *Options, repoMap map[string]RepositoryItem) (bool, error) {
	urlPathFmt := fmt.Sprintf("orgs/%s/code-scanning/alerts?state=open&per_page=100&page=%%d", org)
	description := fmt.Sprintf("org code scanning alerts for %s", org)
	return fetchAlertsOrgPaginated(restClient, urlPathFmt, description, repoMap, func(alert codeScanningAlertResponse) (AdvisoryItem, bool, error) {
		return collectCodeScanningAlert(alert, alert.Repository.FullName, opts)
	})
}

func collectCodeScanningAlertsForRepo(restClient *api.RESTClient, repoFullName string, opts *Options) ([]AdvisoryItem, error) {
	urlPathFmt := fmt.Sprintf("repos/%s/code-scanning/alerts?state=open&per_page=100&page=%%d", repoFullName)
	description := fmt.Sprintf("code scanning alerts for %s", repoFullName)
	return fetchAlertsForRepoPaginated(restClient, urlPathFmt, description, func(alert codeScanningAlertResponse) (AdvisoryItem, bool, error) {
		return collectCodeScanningAlert(alert, repoFullName, opts)
	})
}

func fetchCodeScanningAlerts(restClient *api.RESTClient, owner string, allRepos []string, opts *Options, repoMap map[string]RepositoryItem, pb *ProgressBar) error {
	return fetchAlertsWithFallback(restClient, owner, allRepos, opts, repoMap, pb, fetchCodeScanningAlertsOrg, collectCodeScanningAlertsForRepo)
}

// fetchSecretScanningAlertsOrg reports (false, nil) when the org-level
// endpoint is unavailable (404), signalling the caller to fall back to
// per-repo fetches. Any other error is returned so the caller can surface it
// instead of silently under-reporting alerts.
func fetchSecretScanningAlertsOrg(restClient *api.RESTClient, org string, opts *Options, repoMap map[string]RepositoryItem) (bool, error) {
	urlPathFmt := fmt.Sprintf("orgs/%s/secret-scanning/alerts?state=open&per_page=100&page=%%d", org)
	description := fmt.Sprintf("org secret scanning alerts for %s", org)
	return fetchAlertsOrgPaginated(restClient, urlPathFmt, description, repoMap, func(alert secretScanningAlertResponse) (AdvisoryItem, bool, error) {
		return collectSecretScanningAlert(alert, alert.Repository.FullName, opts)
	})
}

func collectSecretScanningAlertsForRepo(restClient *api.RESTClient, repoFullName string, opts *Options) ([]AdvisoryItem, error) {
	urlPathFmt := fmt.Sprintf("repos/%s/secret-scanning/alerts?state=open&per_page=100&page=%%d", repoFullName)
	description := fmt.Sprintf("secret scanning alerts for %s", repoFullName)
	return fetchAlertsForRepoPaginated(restClient, urlPathFmt, description, func(alert secretScanningAlertResponse) (AdvisoryItem, bool, error) {
		return collectSecretScanningAlert(alert, repoFullName, opts)
	})
}

func fetchSecretScanningAlerts(restClient *api.RESTClient, owner string, allRepos []string, opts *Options, repoMap map[string]RepositoryItem, pb *ProgressBar) error {
	// Secret scanning alerts have no severity; skip when severity filter is active
	if len(opts.Severities) > 0 {
		pb.IncrementBy(len(allRepos))
		return nil
	}
	return fetchAlertsWithFallback(restClient, owner, allRepos, opts, repoMap, pb, fetchSecretScanningAlertsOrg, collectSecretScanningAlertsForRepo)
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
	extraFetches := 0
	if opts.CodeScanning {
		extraFetches++
	}
	if opts.SecretScanning {
		extraFetches++
	}
	pb.AddTotal(len(allRepos) * extraFetches)
	var errs []error
	if opts.CodeScanning {
		if err := fetchCodeScanningAlerts(restClient, owner, allRepos, opts, repoMap, pb); err != nil {
			errs = append(errs, err)
		}
	}
	if opts.SecretScanning {
		if err := fetchSecretScanningAlerts(restClient, owner, allRepos, opts, repoMap, pb); err != nil {
			errs = append(errs, err)
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

	repoNames := make([]string, 0, len(repoMap))
	for name := range repoMap {
		repoNames = append(repoNames, name)
	}
	sort.Strings(repoNames)

	repositories := make([]RepositoryItem, 0, len(repoMap))
	for _, name := range repoNames {
		repositories = append(repositories, repoMap[name])
	}

	return repositories, errors.Join(errs...)
}
