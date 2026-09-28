package config_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chia-network/repo-content-updater/internal/config"
)

func dependencyCursorReviewCompanionFiles(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("dcr_managed_companion_names.golden")
	assert.Nil(t, err)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func TestConfigIsValid(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	for _, group := range cfg.Groups {
		files, err := cfg.ExpandGroup(group.Name)
		assert.Nil(t, err)
		assert.Equal(t, len(group.Templates), len(files))
	}

	dcrGroup, err := cfg.ExpandGroup("dependency-cursor-review")
	assert.Nil(t, err)
	for _, required := range []string{
		"malware-verdict-policy",
		"upstream-malware-scan",
		"dependency-cursor-review-prompts",
		"dependency-cursor-review-combine-outputs",
	} {
		assert.Contains(t, dcrGroup, required)
	}

	// Bugbot d8695a0d: group must ship extracted companions, not formatter bundle alone.
	for _, required := range []string{
		"upstream-malware-scan-lib",
		"dependency-cursor-review-dependabot-context",
		"script-dir-isolated-load",
		"malware-verdict-policy-analysis",
	} {
		assert.Contains(t, dcrGroup, required)
	}

	expected := dependencyCursorReviewCompanionFiles(t)
	expanded, err := cfg.ExpandManagedFileEntries([]string{"dependency-cursor-review"})
	assert.Nil(t, err)
	assert.Equal(t, expected, expanded)

	groupExpanded, err := cfg.ExpandManagedFileEntries([]string{"group:dependency-cursor-review"})
	assert.Nil(t, err)
	assert.Equal(t, expected, groupExpanded)

	mixed, err := cfg.ExpandManagedFileEntries([]string{"group:does-not-exist", "dependabot"})
	assert.Nil(t, err)
	assert.Equal(t, []string{"dependabot"}, mixed)
}

func TestManagedFileAliasesAndPathsIncludeCompanions(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	expected := dependencyCursorReviewCompanionFiles(t)
	for _, entry := range []string{
		"dependabot-cursor-review",
		".github/workflows/dependency-cursor-review.yml",
		".github/workflows/dependabot-cursor-review.yml",
	} {
		expanded, err := cfg.ExpandManagedFileEntries([]string{entry})
		assert.Nil(t, err, entry)
		assert.Equal(t, expected, expanded, entry)
	}
}

func TestEnsureCompanionFilesPairsWorkflowWithFormatter(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	expected := dependencyCursorReviewCompanionFiles(t)
	finalized, err := cfg.EnsureCompanionFiles([]string{"dependency-cursor-review"})
	assert.Nil(t, err)
	assert.Equal(t, expected, finalized)

	legacyFinalized, err := cfg.EnsureCompanionFiles([]string{"dependabot-cursor-review"})
	assert.Nil(t, err)
	assert.Equal(t, expected, legacyFinalized)
}

func TestAmbiguousSharedPathsAreNotUsedForPathLookup(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	for _, sharedPath := range []string{
		".github/dependabot.yml",
		".github/dependabot.yaml",
	} {
		canonical, ok := cfg.ResolveManagedFileName(sharedPath)
		assert.False(t, ok, "path %q must not resolve when shared by dependabot and go-dependabot", sharedPath)
		assert.Empty(t, canonical)
	}

	canonical, ok := cfg.ResolveManagedFileName("dependabot")
	assert.True(t, ok)
	assert.Equal(t, "dependabot", canonical)

	goCanonical, ok := cfg.ResolveManagedFileName("go-dependabot")
	assert.True(t, ok)
	assert.Equal(t, "go-dependabot", goCanonical)

	expanded, err := cfg.ExpandManagedFileEntries([]string{".github/dependabot.yml"})
	assert.Nil(t, err)
	assert.Empty(t, expanded)
}
