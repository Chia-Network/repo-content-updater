package repo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"text/template"
	"time"
)

// ProcessTemplate renders the given template file
func ProcessTemplate(templateContent []byte, overrides map[string]string) ([]byte, error) {
	// Compute the SHA256 hash of the template content
	hash := sha256.Sum256(templateContent)
	hexHash := hex.EncodeToString(hash[:])

	notOverridable := map[string]bool{"CURRENT_YEAR": true}
	defaultPullRequestLimit := "10"
	data := map[string]string{
		"CURRENT_YEAR":                          strconv.Itoa(time.Now().Year()),
		"COMPANY_NAME":                          "Chia Network Inc.",
		"CGO_ENABLED":                           "0",
		"DEPENDABOT_GOMOD_PULL_REQUEST_LIMIT":   defaultPullRequestLimit,
		"DEPENDABOT_GOMOD_DIRECTORY":            "/",
		"DEPENDABOT_GOMOD_REVIEWERS":            "[\"cmmarslender\", \"starttoaster\"]",
		"DEPENDABOT_PIP_PULL_REQUEST_LIMIT":     defaultPullRequestLimit,
		"DEPENDABOT_PIP_DIRECTORY":              "/",
		"DEPENDABOT_PIP_REVIEWERS":              "[\"emlowe\", \"altendky\"]",
		"DEPENDABOT_ACTIONS_PULL_REQUEST_LIMIT": defaultPullRequestLimit,
		"DEPENDABOT_ACTIONS_DIRECTORY":          "/",
		"DEPENDABOT_ACTIONS_REVIEWERS":          "[\"cmmarslender\", \"Starttoaster\", \"pmaslana\"]",
		"DEPENDABOT_NPM_PULL_REQUEST_LIMIT":     defaultPullRequestLimit,
		"DEPENDABOT_NPM_DIRECTORY":              "/",
		"DEPENDABOT_NPM_REVIEWERS":              "[\"cmmarslender\", \"emlowe\"]",
	}

	// Merge `overrides` into `data`, with `overrides` taking precedence
	for key, value := range overrides {
		if notOverridable[key] {
			continue
		}
		data[key] = value
	}

	tmpl, err := template.New(hexHash).Parse(string(templateContent))
	if err != nil {
		return nil, err
	}

	var processedTemplate bytes.Buffer
	if err = tmpl.Execute(&processedTemplate, data); err != nil {
		return nil, err
	}

	return processedTemplate.Bytes(), nil
}
