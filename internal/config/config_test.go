package config_test

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
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

	assert.Equal(t, []string{"dependabot-actions", "dep-review"}, cfg.DefaultFiles)
}

func TestDependencyReviewAcceptsEarlierHeaderMarkers(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	if !assert.Nil(t, err) {
		return
	}

	file := cfg.GetFileInfo("dep-review")
	if !assert.NotNil(t, file) {
		return
	}
	assert.Equal(t, []string{"Managed by repo-content-updater"}, file.PreviousAdoptionMarkers)
}

// TestAdoptionMarkersDoNotMatchOtherTemplates checks that every marker names
// only its own file, so a shared header line cannot adopt a different file.
func TestAdoptionMarkersDoNotMatchOtherTemplates(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	type markerCase struct {
		file   *config.File
		marker string
	}
	var cases []markerCase
	for i := range cfg.Files {
		file := &cfg.Files[i]
		markers := append([]string{}, file.PreviousAdoptionMarkers...)
		if marker := strings.TrimSpace(file.AdoptionMarker); marker != "" {
			markers = append(markers, marker)
		}
		for _, marker := range markers {
			marker = strings.TrimSpace(marker)
			if marker == "" {
				continue
			}
			cases = append(cases, markerCase{file: file, marker: marker})
		}
	}

	for _, tt := range cases {
		t.Run(tt.file.Name+"/"+tt.marker, func(t *testing.T) {
			want := "# " + tt.marker
			for i := range cfg.Files {
				other := &cfg.Files[i]
				if other.Name == tt.file.Name {
					continue
				}
				raw, err := readTemplateForTest(cfg, other.TemplateName)
				if err != nil {
					t.Fatalf("read template %s for %s: %v", other.TemplateName, other.Name, err)
				}
				if containsTrimmedLine(string(raw), want) {
					t.Errorf("marker %q of %q appears as %q in template %q of %q", tt.marker, tt.file.Name, want, other.TemplateName, other.Name)
				}
			}
		})
	}
}

// readTemplateForTest reads the template, falling back to the canonical source
// under internal/workflowscripts when the template is a generated companion.
func readTemplateForTest(cfg *config.Config, templateName string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join("../../templates", templateName))
	if err == nil {
		return raw, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	canonical, ok := canonicalSourceForTemplate(cfg, templateName)
	if !ok {
		return nil, fmt.Errorf("template %s does not exist and has no canonical source", templateName)
	}
	raw, err = os.ReadFile(filepath.Join("../../internal/workflowscripts", canonical))
	if err != nil {
		return nil, fmt.Errorf("read canonical source %s: %w", canonical, err)
	}
	return raw, nil
}

// canonicalSourceForTemplate applies the same mapping as
// sync_canonical_to_template: generated companions come from .github/scripts/
// entries, with the basename of repo_path as the canonical filename.
func canonicalSourceForTemplate(cfg *config.Config, templateName string) (string, bool) {
	const canonicalOverride = "github_scripts_init.py"
	for i := range cfg.Files {
		file := &cfg.Files[i]
		if file.TemplateName != templateName || !strings.HasPrefix(file.RepoPath, ".github/scripts/") {
			continue
		}
		if templateName == "github-scripts-init.py" {
			return canonicalOverride, true
		}
		return filepath.Base(file.RepoPath), true
	}
	return "", false
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
		"github-scripts-init",
		"dependency-artifact-review-fetch",
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

func TestResolveManagedFileSelection(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	t.Run("defaults are added to every repo", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", nil)
		assert.Empty(t, selection.Explicit)
		assert.Equal(t, []string{"dependabot-actions", "dep-review"}, defaultNames(selection))
		if assert.Len(t, selection.Defaults, 2) {
			assert.Equal(t, config.DefaultBundle{Root: "dependabot-actions", Files: []string{"dependabot-actions"}}, selection.Defaults[0])
			assert.Equal(t, config.DefaultBundle{Root: "dep-review", Files: []string{"dep-review"}}, selection.Defaults[1])
		}
	})

	t.Run("default resolves to the manifest-aware dependabot template", func(t *testing.T) {
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
		t.Run(optOut+" removes the dependabot default and keeps the review default", func(t *testing.T) {
			selection := cfg.ResolveManagedFileSelection("repo", []string{optOut})
			assert.Empty(t, selection.Explicit)
			names := defaultNames(selection)
			assert.NotContains(t, names, "dependabot-actions")
			assert.Contains(t, names, "dep-review")
		})
	}

	t.Run("opt-out of the dependency review default removes it", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"!dep-review"})
		assert.NotContains(t, defaultNames(selection), "dep-review")
		assert.Contains(t, defaultNames(selection), "dependabot-actions")
	})

	t.Run("opt-out removes an explicitly selected file", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"group:base", "!dependabot", "!dep-review"})
		assert.NotContains(t, selection.Explicit, "dependabot")
		assert.NotContains(t, selection.Explicit, "dep-review")
		assert.Empty(t, selection.Defaults)
	})

	t.Run("explicit artifact review keeps the defaults", func(t *testing.T) {
		selection := cfg.ResolveManagedFileSelection("repo", []string{"dependency-artifact-review"})
		assert.Contains(t, selection.Explicit, "dependency-artifact-review")
		assert.Contains(t, selection.Explicit, "dependency-artifact-review-fetch")
		assert.Equal(t, []string{"dependabot-actions", "dep-review"}, defaultNames(selection))
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

func TestRetiredLegacyDependencyReviewPathsAreNoLongerManaged(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	file := cfg.GetFileInfo("dep-review")
	if !assert.NotNil(t, file) {
		return
	}
	for _, retired := range []string{
		".github/workflows/dependency-cursor-review.yml",
		".github/workflows/dependency-cursor-review.yaml",
		".github/workflows/dependabot-cursor-review.yml",
		".github/workflows/dependabot-cursor-review.yaml",
		".github/actions/trusted-git-path-checkout/action.yml",
		".github/scripts/malware_verdict_formatter.py",
		".github/scripts/upstream_malware_scan.sh",
		".github/scripts/dependency_manifest_versions.py",
		".github/scripts/upstream_release_checkout.sh",
	} {
		assert.Contains(t, file.RetiredPaths, retired)
	}
	for _, retired := range file.RetiredPaths {
		_, ok := cfg.ResolveManagedFileName(retired)
		assert.False(t, ok, retired)
	}
	assert.NotContains(t, file.RetiredPaths, ".github/scripts/__init__.py")
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

func containsTrimmedLine(content, want string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}
