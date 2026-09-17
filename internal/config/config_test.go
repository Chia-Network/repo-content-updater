package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chia-network/repo-content-updater/internal/config"
)

func TestConfigIsValid(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	for _, group := range cfg.Groups {
		files, err := cfg.ExpandGroup(group.Name)
		assert.Nil(t, err)
		assert.Equal(t, len(group.Templates), len(files))
	}

	expanded, err := cfg.ExpandManagedFileEntries([]string{"dependency-cursor-review"})
	assert.Nil(t, err)
	assert.Equal(t, []string{"dependency-cursor-review", "malware-verdict-formatter"}, expanded)

	groupExpanded, err := cfg.ExpandManagedFileEntries([]string{"group:dependency-cursor-review"})
	assert.Nil(t, err)
	assert.Equal(t, []string{"dependency-cursor-review", "malware-verdict-formatter"}, groupExpanded)

	mixed, err := cfg.ExpandManagedFileEntries([]string{"group:does-not-exist", "dependabot"})
	assert.Nil(t, err)
	assert.Equal(t, []string{"dependabot"}, mixed)
}

func TestManagedFileAliasesAndPathsIncludeCompanions(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	for _, entry := range []string{
		"dependabot-cursor-review",
		".github/workflows/dependency-cursor-review.yml",
		".github/workflows/dependabot-cursor-review.yml",
	} {
		expanded, err := cfg.ExpandManagedFileEntries([]string{entry})
		assert.Nil(t, err, entry)
		assert.Equal(
			t,
			[]string{"dependency-cursor-review", "malware-verdict-formatter"},
			expanded,
			entry,
		)
	}
}

func TestEnsureCompanionFilesPairsWorkflowWithFormatter(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	// Simulates pre-#163 managed-files binaries that pass a flat file list without
	// ExpandManagedFileEntries companion expansion.
	finalized, err := cfg.EnsureCompanionFiles([]string{"dependency-cursor-review"})
	assert.Nil(t, err)
	assert.Equal(t, []string{"dependency-cursor-review", "malware-verdict-formatter"}, finalized)

	legacyFinalized, err := cfg.EnsureCompanionFiles([]string{"dependabot-cursor-review"})
	assert.Nil(t, err)
	assert.Equal(t, []string{"dependency-cursor-review", "malware-verdict-formatter"}, legacyFinalized)
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
