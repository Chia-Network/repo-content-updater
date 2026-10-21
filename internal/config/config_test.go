package config_test

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
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
		"malware-verdict-formatter",
		"upstream-malware-scan",
		"dependency-cursor-review-prompts",
		"dependency-cursor-review-combine-outputs",
	} {
		assert.Contains(t, dcrGroup, required)
	}

	// Extracted companions must ship with the group; the prose policy stack is gone.
	for _, required := range []string{
		"upstream-malware-scan-lib",
		"upstream-malware-scan-findings",
		"upstream-release-checkout",
		"dependency-cursor-review-dependabot-context",
		"trusted-formatter-loader",
		"isolated-module-exec",
		"formatter-runtime-bundle",
	} {
		assert.Contains(t, dcrGroup, required)
	}
	for _, removed := range []string{
		"malware-verdict-policy",
		"malware-verdict-policy-rules-select",
		"malware-verdict-policy-predicates",
		"malware-verdict-policy-analysis",
		"malware-verdict-patterns",
		"malware-verdict-patterns-regex",
		"malware-verdict-patterns-structure",
	} {
		assert.NotContains(t, dcrGroup, removed)
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

func TestResolveManagedFileSelection(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	t.Run("defaults are added to every repo", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", nil)
		assert.Empty(t, selection.Explicit)
		assert.Equal(t, []string{"dependabot-actions"}, selection.Defaults)
	})

	t.Run("default resolves to the github-actions template", func(t *testing.T) {
		assert.Equal(t, []string{"dependabot-actions"}, cfg.DefaultFiles)
		file := cfg.GetFileInfo("dependabot-actions")
		if assert.NotNil(t, file) {
			assert.Equal(t, "dependabot-actions.yml", file.TemplateName)
			assert.Equal(t, ".github/dependabot.yml", file.RepoPath)
			assert.Equal(t, []string{".github/dependabot.yaml"}, file.AlternatePaths)
		}
	})

	t.Run("opt-out of dependabot removes the default via its shared repo path", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"!dependabot"})
		assert.Empty(t, selection.Explicit)
		assert.Empty(t, selection.Defaults)
	})

	t.Run("opt-out of go-dependabot removes the default via its shared repo path", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"!go-dependabot"})
		assert.Empty(t, selection.Explicit)
		assert.Empty(t, selection.Defaults)
	})

	t.Run("opt-out of dependabot-actions removes the default", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"!dependabot-actions"})
		assert.Empty(t, selection.Explicit)
		assert.Empty(t, selection.Defaults)
	})

	t.Run("opt-out removes an explicitly selected file", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"group:base", "!dependabot"})
		assert.NotContains(t, selection.Explicit, "dependabot")
		assert.Contains(t, selection.Explicit, "dep-review")
		assert.Empty(t, selection.Defaults)
	})

	t.Run("opt-out removes an explicit file and its companions", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"dependency-cursor-review", "!dependency-cursor-review", "!dependabot"})
		assert.Empty(t, selection.Explicit)
		assert.Empty(t, selection.Defaults)
	})

	t.Run("opt-out of a required companion is rejected", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"dependency-cursor-review", "!malware-verdict-formatter"})
		assert.Contains(t, selection.Explicit, "dependency-cursor-review")
		assert.Contains(t, selection.Explicit, "malware-verdict-formatter")
	})

	t.Run("go-dependabot suppresses the default via its shared repo path", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"go-dependabot"})
		assert.Equal(t, []string{"go-dependabot"}, selection.Explicit)
		assert.Empty(t, selection.Defaults)
	})

	t.Run("explicit dependabot suppresses the default via its shared repo path", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"dependabot"})
		assert.Equal(t, []string{"dependabot"}, selection.Explicit)
		assert.Empty(t, selection.Defaults)
	})
}

func TestResolveManagedFileSelectionDropsSelectionWithUnknownCompanion(t *testing.T) {
	cfg := loadSelectionTestConfig(t, `
files:
  - name: workflow
    template_name: workflow.yml
    repo_path: .github/workflows/workflow.yml
    companion_files:
      - does-not-exist
`)

	selection := cfg.ResolveManagedFileSelection("repo", []string{"workflow"})
	assert.Empty(t, selection.Explicit)
}

func TestResolveManagedFileSelectionDefaultCompanions(t *testing.T) {
	cfg := loadSelectionTestConfig(t, `
default_files:
  - workflow
files:
  - name: workflow
    template_name: workflow.yml
    repo_path: .github/workflows/workflow.yml
    companion_files:
      - script
    adoption_marker: test:workflow
  - name: script
    template_name: script.sh
    repo_path: .github/scripts/script.sh
    adoption_marker: test:script
`)

	t.Run("default includes companions", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", nil)
		assert.Equal(t, []string{"workflow", "script"}, selection.Defaults)
	})

	t.Run("opt-out of a required default companion is rejected", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"!script"})
		assert.Equal(t, []string{"workflow", "script"}, selection.Defaults)
	})

	t.Run("opt-out of a default root removes its companions", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"!workflow"})
		assert.Empty(t, selection.Defaults)
	})
}

func loadSelectionTestConfig(t *testing.T, contents string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(path, []byte(contents), 0o644)
	assert.Nil(t, err)
	cfg, err := config.LoadConfig(path)
	assert.Nil(t, err)
	return cfg
}

func TestUnknownManagedFileLogIncludesRepo(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	var logs bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	}()

	selection := cfg.ResolveManagedFileSelection("example-repo", []string{"does-not-exist"})
	assert.Empty(t, selection.Explicit)
	assert.Contains(t, logs.String(), "does-not-exist")
	assert.Contains(t, logs.String(), "example-repo")
}

func TestLoadConfigRejectsUnknownDefaultFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(path, []byte(`
default_files:
  - does-not-exist
files:
  - name: dependabot
    template_name: dependabot.yml
    repo_path: .github/dependabot.yml
`), 0o644)
	assert.Nil(t, err)

	_, err = config.LoadConfig(path)
	assert.ErrorContains(t, err, "does-not-exist")
}

func TestLoadConfigRejectsDefaultPathCollision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(path, []byte(`
default_files:
  - first
  - second
files:
  - name: first
    template_name: first.yml
    repo_path: .github/dependabot.yml
  - name: second
    template_name: second.yml
    repo_path: .github/dependabot.yml
`), 0o644)
	assert.Nil(t, err)

	_, err = config.LoadConfig(path)
	assert.ErrorContains(t, err, "same repo path")
}

func TestLoadConfigRejectsDefaultFileWithoutAdoptionMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(path, []byte(`
default_files:
  - first
files:
  - name: first
    template_name: first.yml
    repo_path: .github/first.yml
`), 0o644)
	assert.Nil(t, err)

	_, err = config.LoadConfig(path)
	assert.ErrorContains(t, err, "adoption_marker")
	assert.ErrorContains(t, err, "first")
}

func TestLoadConfigRejectsDuplicateAdoptionMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(path, []byte(`
files:
  - name: first
    template_name: first.yml
    repo_path: .github/first.yml
    adoption_marker: shared-marker
  - name: second
    template_name: second.yml
    repo_path: .github/second.yml
    adoption_marker: shared-marker
`), 0o644)
	assert.Nil(t, err)

	_, err = config.LoadConfig(path)
	assert.ErrorContains(t, err, "adoption_marker")
	assert.ErrorContains(t, err, "shared-marker")
}

func TestAmbiguousSharedPathsAreNotUsedForPathLookup(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	for _, sharedPath := range []string{
		".github/dependabot.yml",
		".github/dependabot.yaml",
	} {
		canonical, ok := cfg.ResolveManagedFileName(sharedPath)
		assert.False(t, ok, "path %q must not resolve when shared by dependabot, go-dependabot, and dependabot-actions", sharedPath)
		assert.Empty(t, canonical)
	}

	canonical, ok := cfg.ResolveManagedFileName("dependabot")
	assert.True(t, ok)
	assert.Equal(t, "dependabot", canonical)

	goCanonical, ok := cfg.ResolveManagedFileName("go-dependabot")
	assert.True(t, ok)
	assert.Equal(t, "go-dependabot", goCanonical)

	actionsCanonical, ok := cfg.ResolveManagedFileName("dependabot-actions")
	assert.True(t, ok)
	assert.Equal(t, "dependabot-actions", actionsCanonical)

	expanded, err := cfg.ExpandManagedFileEntries([]string{".github/dependabot.yml"})
	assert.Nil(t, err)
	assert.Empty(t, expanded)
}
