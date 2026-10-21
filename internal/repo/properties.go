package repo

import (
	"context"
	"strings"

	"github.com/google/go-github/v59/github"
)

type repoPropertyEntry struct {
	name         string
	managedFiles []string
	props        CustomProperties
}

// loadRepoProperties fetches custom properties as a lookup for explicit
// managed-file selections. If onlyRepo is set, a single targeted API call is
// made for that repo instead of paginating the full org list.
func (c *Content) loadRepoProperties(onlyRepo string) (map[string]repoPropertyEntry, error) {
	result := map[string]repoPropertyEntry{}

	if onlyRepo != "" {
		values, _, err := ghDo(func() ([]*github.CustomPropertyValue, *github.Response, error) {
			return c.githubClient.Repositories.GetAllCustomPropertyValues(context.TODO(), c.githubOrg, onlyRepo)
		})
		if err != nil {
			return nil, err
		}
		result[strings.ToLower(onlyRepo)] = newRepoPropertyEntry(onlyRepo, values)
		return result, nil
	}

	opts := &github.ListOptions{
		Page:    0,
		PerPage: 100,
	}
	for {
		opts.Page++
		page, resp, err := ghDo(func() ([]*github.RepoCustomPropertyValue, *github.Response, error) {
			return c.githubClient.Organizations.ListCustomPropertyValues(context.TODO(), c.githubOrg, opts)
		})
		if err != nil {
			return nil, err
		}
		for _, repo := range page {
			result[strings.ToLower(repo.RepositoryName)] = newRepoPropertyEntry(repo.RepositoryName, repo.Properties)
		}
		if resp.NextPage == 0 {
			break
		}
	}
	return result, nil
}

func newRepoPropertyEntry(name string, properties []*github.CustomPropertyValue) repoPropertyEntry {
	return repoPropertyEntry{
		name:         name,
		managedFiles: managedFileEntries(properties),
		props:        parseCustomProperties(properties),
	}
}

func managedFileEntries(properties []*github.CustomPropertyValue) []string {
	for _, property := range properties {
		if property.PropertyName == "managed-files" && property.Value != nil {
			return strings.Split(*property.Value, ",")
		}
	}
	return nil
}

// GetResolvedProperties fetches custom properties and returns the parsed
// CustomProperties for each repo.
func (c *Content) GetResolvedProperties(onlyRepo string) (map[string]CustomProperties, error) {
	entries, err := c.loadRepoProperties(onlyRepo)
	if err != nil {
		return nil, err
	}
	result := make(map[string]CustomProperties, len(entries))
	for _, entry := range entries {
		result[entry.name] = entry.props
	}
	return result, nil
}

// parseCustomProperties extracts the tool-relevant custom properties from
// a repo's raw GitHub property list.
func parseCustomProperties(properties []*github.CustomPropertyValue) CustomProperties {
	var props CustomProperties
	for _, p := range properties {
		if p.PropertyName == "repo-content-updater-bypass-pr" && p.Value != nil && *p.Value == "true" {
			props.BypassPR = true
		}
	}
	return props
}
