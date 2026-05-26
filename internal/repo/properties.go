package repo

import (
	"context"

	"github.com/google/go-github/v59/github"
)

// GetResolvedProperties fetches custom properties and returns the parsed
// CustomProperties for each repo. If onlyRepo is set, a single targeted
// API call is made for that repo instead of paginating the full org list.
func (c *Content) GetResolvedProperties(onlyRepo string) (map[string]CustomProperties, error) {
	if onlyRepo != "" {
		return c.getResolvedPropertiesForRepo(onlyRepo)
	}
	return c.getResolvedPropertiesForOrg()
}

func (c *Content) getResolvedPropertiesForRepo(repoName string) (map[string]CustomProperties, error) {
	values, _, err := ghDo(func() ([]*github.CustomPropertyValue, *github.Response, error) {
		return c.githubClient.Repositories.GetAllCustomPropertyValues(context.TODO(), c.githubOrg, repoName)
	})
	if err != nil {
		return nil, err
	}
	return map[string]CustomProperties{
		repoName: parseCustomProperties(values),
	}, nil
}

func (c *Content) getResolvedPropertiesForOrg() (map[string]CustomProperties, error) {
	result := map[string]CustomProperties{}

	opts := &github.ListOptions{
		Page:    0,
		PerPage: 100,
	}
	for {
		opts.Page++
		repos, resp, err := ghDo(func() ([]*github.RepoCustomPropertyValue, *github.Response, error) {
			return c.githubClient.Organizations.ListCustomPropertyValues(context.TODO(), c.githubOrg, opts)
		})
		if err != nil {
			return nil, err
		}

		for _, repo := range repos {
			result[repo.RepositoryName] = parseCustomProperties(repo.Properties)
		}

		if resp.NextPage == 0 {
			break
		}
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
