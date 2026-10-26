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

	dcrGroup, err := cfg.ExpandManagedFileEntries([]string{"group:dependency-cursor-review"})
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

func TestDependencyArtifactReviewIsOptInOnly(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	assert.NotContains(t, cfg.DefaultFiles, "dependency-artifact-review")
	selection := cfg.ResolveManagedFileSelection("repo", nil)
	assert.NotContains(t, defaultNames(selection), "dependency-artifact-review")

	expanded, err := cfg.ExpandManagedFileEntries([]string{"dependency-artifact-review"})
	assert.Nil(t, err)
	assert.Equal(t, []string{
		"dependency-artifact-review",
		"dependency-artifact-review-fetch",
		"dependency-artifact-review-sources",
		"dependency-artifact-review-lock",
		"dependency-artifact-review-verdict",
		"dependency-artifact-review-prompt",
	}, expanded)

	groupExpanded, err := cfg.ExpandManagedFileEntries([]string{"group:dependency-artifact-review"})
	assert.Nil(t, err)
	assert.Equal(t, expanded, groupExpanded)

	file := cfg.GetFileInfo("dependency-artifact-review")
	if assert.NotNil(t, file) {
		assert.Equal(t, "dependency-artifact-review.yml", file.TemplateName)
		assert.Equal(t, ".github/workflows/dependency-artifact-review.yml", file.RepoPath)
		assert.Equal(t, "repo-content-updater:dependency-artifact-review", file.AdoptionMarker)
		assert.Equal(t, []string{".github/workflows"}, file.RequiresPaths)
	}
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

func TestRenamedVersionsCompanionKeepsItsOldNameAndPath(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	for _, entry := range []string{
		"dependency-manifest-versions",
		".github/scripts/dependency_manifest_versions.py",
		".github/scripts/dependency_cursor_review_versions.py",
	} {
		canonical, ok := cfg.ResolveManagedFileName(entry)
		assert.True(t, ok, entry)
		assert.Equal(t, "dependency-cursor-review-versions", canonical, entry)
	}
	file := cfg.GetFileInfo("dependency-cursor-review-versions")
	if assert.NotNil(t, file) {
		assert.Equal(t, []string{".github/scripts/dependency_manifest_versions.py"}, file.AlternatePaths)
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
		cursorBundle, err := cfg.EnsureCompanionFiles([]string{"dependency-cursor-review"})
		assert.Nil(t, err)
		expectedDefaults := append([]string{"dependabot-actions"}, cursorBundle...)
		expectedDefaults = append(expectedDefaults, "dep-review")
		assert.Equal(t, expectedDefaults, defaultNames(selection))
		if assert.Len(t, selection.Defaults, 3) {
			assert.Equal(t, config.DefaultBundle{Root: "dependabot-actions", Files: []string{"dependabot-actions"}}, selection.Defaults[0])
			assert.Equal(t, config.DefaultBundle{Root: "dependency-cursor-review", Files: cursorBundle}, selection.Defaults[1])
			assert.Equal(t, config.DefaultBundle{Root: "dep-review", Files: []string{"dep-review"}}, selection.Defaults[2])
		}
	})

	t.Run("opting out of a review companion drops the whole review bundle", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"!malware-verdict-formatter"})
		assert.Equal(t, []string{"dependabot-actions", "dep-review"}, defaultNames(selection))
	})

	t.Run("default resolves to the manifest-aware dependabot template", func(t *testing.T) {
		assert.Equal(t, []string{"dependabot-actions", "dependency-cursor-review", "dep-review"}, cfg.DefaultFiles)
		file := cfg.GetFileInfo("dependabot-actions")
		if assert.NotNil(t, file) {
			assert.Equal(t, "dependabot.yml", file.TemplateName)
			assert.Equal(t, ".github/dependabot.yml", file.RepoPath)
			assert.Equal(t, []string{".github/dependabot.yaml"}, file.AlternatePaths)
			assert.Equal(t, []string{".github/workflows"}, file.RequiresPaths)
		}
		depReview := cfg.GetFileInfo("dep-review")
		if assert.NotNil(t, depReview) {
			assert.Equal(t, "repo-content-updater:dependency-review", depReview.AdoptionMarker)
			assert.Equal(t, []string{".github/workflows"}, depReview.RequiresPaths)
		}
	})

	for _, optOut := range []string{"!dependabot", "!go-dependabot", "!dependabot-actions"} {
		t.Run(optOut+" removes the dependabot default and keeps the review bundle", func(t *testing.T) {
			selection := cfg.ResolveManagedFileSelection("repo", []string{optOut})
			assert.Empty(t, selection.Explicit)
			names := defaultNames(selection)
			assert.NotContains(t, names, "dependabot-actions")
			assert.Contains(t, names, "dependency-cursor-review")
			assert.Contains(t, names, "dep-review")
		})
	}

	for _, optOut := range []string{"!dependency-cursor-review", "!dependabot-cursor-review"} {
		t.Run(optOut+" removes the review bundle and keeps the dependabot default", func(t *testing.T) {
			selection := cfg.ResolveManagedFileSelection("repo", []string{optOut})
			assert.Equal(t, []string{"dependabot-actions", "dep-review"}, defaultNames(selection))
		})
	}

	t.Run("opt-out of the dependency review default removes it", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"!dep-review"})
		assert.NotContains(t, defaultNames(selection), "dep-review")
		assert.Contains(t, defaultNames(selection), "dependabot-actions")
	})

	t.Run("opt-out removes an explicitly selected file", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"group:base", "!dependabot", "!dependency-cursor-review"})
		assert.NotContains(t, selection.Explicit, "dependabot")
		assert.Contains(t, selection.Explicit, "dep-review")
		assert.Empty(t, selection.Defaults)
	})

	t.Run("opt-out removes an explicit file and its companions", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"dependency-cursor-review", "!dependency-cursor-review", "!dependabot"})
		assert.Empty(t, selection.Explicit)
		assert.Equal(t, []string{"dep-review"}, defaultNames(selection))
	})

	t.Run("explicit review suppresses the review bundle", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"dependency-cursor-review"})
		assert.Contains(t, selection.Explicit, "upstream-release-checkout")
		assert.Equal(t, []string{"dependabot-actions", "dep-review"}, defaultNames(selection))
	})

	t.Run("an explicit companion stays explicit inside the review bundle", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"upstream-release-checkout"})
		assert.Equal(t, []string{"upstream-release-checkout"}, selection.Explicit)
		names := defaultNames(selection)
		assert.Contains(t, names, "dependency-cursor-review")
		assert.NotContains(t, names, "upstream-release-checkout")
	})

	t.Run("opt-out of a required companion is rejected", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"dependency-cursor-review", "!malware-verdict-formatter"})
		assert.Contains(t, selection.Explicit, "dependency-cursor-review")
		assert.Contains(t, selection.Explicit, "malware-verdict-formatter")
	})

	t.Run("go-dependabot suppresses the default via its shared repo path", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"go-dependabot"})
		assert.Equal(t, []string{"go-dependabot"}, selection.Explicit)
		assert.NotContains(t, defaultNames(selection), "dependabot-actions")
	})

	t.Run("explicit dependabot suppresses the default via its shared repo path", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"dependabot"})
		assert.Equal(t, []string{"dependabot"}, selection.Explicit)
		assert.NotContains(t, defaultNames(selection), "dependabot-actions")
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
`)

	t.Run("default includes companions", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", nil)
		assert.Equal(t, []string{"workflow", "script"}, defaultNames(selection))
	})

	t.Run("opt-out of a default companion drops the bundle", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"!script"})
		assert.Empty(t, selection.Defaults)
	})

	t.Run("opt-out of a default root removes its companions", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"!workflow"})
		assert.Empty(t, selection.Defaults)
	})
}

func TestResolveManagedFileNameMatchesNonCanonicalRepoPath(t *testing.T) {
	cfg := loadSelectionTestConfig(t, `
default_files:
  - first
files:
  - name: first
    template_name: first.yml
    repo_path: .github//first.yml
    adoption_marker: test:first
`)

	for _, entry := range []string{".github//first.yml", ".github/first.yml", ".github/./first.yml"} {
		t.Run(entry, func(t *testing.T) {
			canonical, ok := cfg.ResolveManagedFileName(entry)
			assert.True(t, ok)
			assert.Equal(t, "first", canonical)

			selection := cfg.ResolveManagedFileSelection("repo", []string{entry})
			assert.Len(t, selection.Explicit, 1)

			selection = cfg.ResolveManagedFileSelection("repo", []string{"!" + entry})
			assert.Empty(t, selection.Explicit)
			assert.Empty(t, selection.Defaults)
		})
	}
}

func defaultNames(selection config.ManagedFileSelection) []string {
	var names []string
	for _, bundle := range selection.Defaults {
		names = append(names, bundle.Files...)
	}
	return names
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

func TestLoadConfigRejectsInvalidRequiresPaths(t *testing.T) {
	tests := []struct {
		name     string
		required string
		wantErr  string
	}{
		{name: "parent traversal", required: "../outside", wantErr: "must not contain '..'"},
		{name: "nested parent traversal", required: ".github/../outside", wantErr: "must not contain '..'"},
		{name: "absolute", required: "/etc/passwd", wantErr: "must be relative"},
		{name: "empty", required: `""`, wantErr: "empty entry"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			err := os.WriteFile(path, []byte(`
files:
  - name: first
    template_name: first.yml
    repo_path: .github/first.yml
    requires_paths:
      - `+tt.required+`
`), 0o644)
			assert.Nil(t, err)

			_, err = config.LoadConfig(path)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestRetiredDependencyCursorReviewPathsAreNoLongerManaged(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	file := cfg.GetFileInfo("dependency-cursor-review")
	if !assert.NotNil(t, file) {
		return
	}
	// The trusted loader stack and the trusted checkout action, removed with their config entries.
	assert.Equal(t, []string{
		".github/actions/trusted-git-path-checkout/action.yml",
		".github/scripts/dependency-cursor-review-trusted-scripts.paths",
		".github/scripts/formatter_runtime_bundle.py",
		".github/scripts/isolated_module_exec.py",
		".github/scripts/scripts_dir_disk_exec.py",
		".github/scripts/scripts_dir_path_scrub.py",
		".github/scripts/trusted_formatter_loader.py",
		".github/scripts/trusted_formatter_loader_cold_start.py",
	}, file.RetiredPaths)
	for _, retired := range file.RetiredPaths {
		_, ok := cfg.ResolveManagedFileName(retired)
		assert.False(t, ok, retired)
	}
}

func TestLoadConfigRejectsInvalidRetiredPaths(t *testing.T) {
	tests := []struct {
		name    string
		retired string
		wantErr string
	}{
		{name: "parent traversal", retired: "../outside", wantErr: "retired_paths entry \"../outside\" must not contain '..'"},
		{name: "absolute", retired: "/etc/passwd", wantErr: "retired_paths entry \"/etc/passwd\" must be relative"},
		{name: "empty", retired: `""`, wantErr: "retired_paths contains an empty entry"},
		{name: "its own path", retired: ".github/first.yml", wantErr: "is still a managed path"},
		{name: "its own alternate path", retired: ".github/first.yaml", wantErr: "is still a managed path"},
		{name: "another file's path", retired: "./.GitHub/second.yml", wantErr: "is still a managed path"},
		{name: "a dot segment", retired: ".github/./second.yml", wantErr: "is still a managed path"},
		{name: "a doubled slash", retired: ".github//second.yml", wantErr: "is still a managed path"},
		{name: "a backslash", retired: `.github\\second.yml`, wantErr: "is still a managed path"},
		{name: "a dot segment in a managed path", retired: ".github/third.yml", wantErr: "is still a managed path"},
		{name: "a doubled slash in a managed path", retired: ".github/fourth.yml", wantErr: "is still a managed path"},
		{name: "a trailing slash", retired: ".github/second.yml/", wantErr: "must name a file"},
		{name: "the repo root", retired: "./", wantErr: "must name a file"},
		{name: "a lone dot", retired: ".", wantErr: "must name a file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			err := os.WriteFile(path, []byte(`
files:
  - name: first
    template_name: first.yml
    repo_path: .github/first.yml
    alternate_paths:
      - .github/first.yaml
    retired_paths:
      - `+tt.retired+`
  - name: second
    template_name: second.yml
    repo_path: .github/second.yml
  - name: third
    template_name: third.yml
    repo_path: .github/./third.yml
  - name: fourth
    template_name: fourth.yml
    repo_path: .github//fourth.yml
`), 0o644)
			assert.Nil(t, err)

			_, err = config.LoadConfig(path)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
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

func TestLoadConfigRejectsPreviousAdoptionMarkerCollision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(path, []byte(`
files:
  - name: first
    template_name: first.yml
    repo_path: .github/first.yml
    adoption_marker: current-marker
  - name: second
    template_name: second.yml
    repo_path: .github/second.yml
    adoption_marker: other-marker
    previous_adoption_markers:
      - current-marker
`), 0o644)
	assert.Nil(t, err)

	_, err = config.LoadConfig(path)
	assert.ErrorContains(t, err, "adoption_marker")
	assert.ErrorContains(t, err, "current-marker")
}

// TestLoadConfigNamesThePreviousMarkerInACollision reports a collision with
// the field each marker came from, so a clash with a previous marker is not
// reported as two current adoption markers.
func TestLoadConfigNamesThePreviousMarkerInACollision(t *testing.T) {
	for name, tt := range map[string]struct{ first, second, want string }{
		"current collides with an earlier previous marker": {
			first:  "adoption_marker: first-marker\n    previous_adoption_markers: [old-marker]",
			second: "adoption_marker: old-marker",
			want:   `adoption_marker "old-marker" of "second" is already the previous_adoption_marker of "first"`,
		},
		"previous collides with an earlier current marker": {
			first:  "adoption_marker: old-marker",
			second: "adoption_marker: second-marker\n    previous_adoption_markers: [old-marker]",
			want:   `previous_adoption_marker "old-marker" of "second" is already the adoption_marker of "first"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			body := "files:\n" +
				"  - name: first\n    template_name: first.yml\n    repo_path: .github/first.yml\n    " + tt.first + "\n" +
				"  - name: second\n    template_name: second.yml\n    repo_path: .github/second.yml\n    " + tt.second + "\n"
			assert.Nil(t, os.WriteFile(path, []byte(body), 0o644))
			_, err := config.LoadConfig(path)
			assert.ErrorContains(t, err, tt.want)
		})
	}
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

func TestLoadConfigRejectsMultilineAdoptionMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(path, []byte(`
default_files:
  - first
files:
  - name: first
    template_name: first.yml
    repo_path: .github/first.yml
    adoption_marker: "ok\nversion: 9"
`), 0o644)
	assert.Nil(t, err)

	_, err = config.LoadConfig(path)
	assert.ErrorContains(t, err, "adoption_marker")
}
