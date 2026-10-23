package repo

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/chia-network/repo-content-updater/internal/config"
)

func TestDependabotNPMOnlyRepoSkipsOtherEcosystems(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	repoDir := t.TempDir()
	writeDependabotTestFile(t, repoDir, "package.json", "{}")

	vars, err := DependabotVarsForRepo(repoDir, cfg.Variables, nil)
	if err != nil {
		t.Fatal(err)
	}
	rendered := renderDependabotTemplate(t, cfg, vars)

	if got, want := renderedDependabotEcosystems(t, rendered), "npm"; got != want {
		t.Fatalf("ecosystems = %q, want %q\n%s", got, want, rendered)
	}
}

func TestDependabotWithAllManifestsMatchesFullTemplate(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	repoDir := t.TempDir()
	for _, manifest := range []string{
		"go.mod",
		"requirements.txt",
		"package.json",
		"Cargo.toml",
		"Package.swift",
		"Dockerfile",
		"main.tf",
		"App.csproj",
	} {
		writeDependabotTestFile(t, repoDir, manifest, "")
	}
	writeDependabotTestFile(t, repoDir, filepath.Join(".github", "workflows", "test.yml"), "")

	vars, err := DependabotVarsForRepo(repoDir, cfg.Variables, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := renderDependabotTemplate(t, cfg, vars)
	want := renderDependabotTemplate(t, cfg, cfg.Variables)

	if !bytes.Equal(got, want) {
		t.Fatalf("all-manifest repo changed the rendered template\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	if got, want := renderedDependabotEcosystems(t, got), "gomod,pip,github-actions,npm,cargo,swift,docker,terraform,nuget"; got != want {
		t.Fatalf("ecosystems = %q, want %q", got, want)
	}
}

func TestDependabotUsesConfiguredEcosystemDirectory(t *testing.T) {
	repoDir := t.TempDir()
	writeDependabotTestFile(t, repoDir, filepath.Join("sub", "go.mod"), "")
	writeDependabotTestFile(t, repoDir, filepath.Join("sub", "requirements-dev.txt"), "")

	vars, err := DependabotEcosystemVars(repoDir, map[string]string{
		"DEPENDABOT_GOMOD_DIRECTORY": "/sub",
		"DEPENDABOT_PIP_DIRECTORY":   "sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"DEPENDABOT_GOMOD_ENABLED", "DEPENDABOT_PIP_ENABLED"} {
		if vars[key] != "1" {
			t.Errorf("%s = %q, want 1", key, vars[key])
		}
	}
	if vars["DEPENDABOT_NPM_ENABLED"] != "0" {
		t.Errorf("DEPENDABOT_NPM_ENABLED = %q, want 0", vars["DEPENDABOT_NPM_ENABLED"])
	}
}

func TestDependabotPipManifests(t *testing.T) {
	for _, manifest := range []string{
		"requirements.txt",
		"requirements-dev.txt",
		"dev-requirements.txt",
		"requirements.in",
		"pyproject.toml",
		"setup.py",
		"setup.cfg",
		"Pipfile",
	} {
		t.Run(manifest, func(t *testing.T) {
			repoDir := t.TempDir()
			writeDependabotTestFile(t, repoDir, manifest, "")
			vars, err := DependabotEcosystemVars(repoDir, nil)
			if err != nil {
				t.Fatal(err)
			}
			if vars["DEPENDABOT_PIP_ENABLED"] != "1" {
				t.Fatalf("DEPENDABOT_PIP_ENABLED = %q, want 1", vars["DEPENDABOT_PIP_ENABLED"])
			}
		})
	}
}

func TestDependabotPipManifestsOneLevelDown(t *testing.T) {
	for _, manifest := range []string{
		filepath.Join("sub", "requirements.txt"),
		filepath.Join("sub", "requirements-dev.in"),
	} {
		t.Run(manifest, func(t *testing.T) {
			repoDir := t.TempDir()
			writeDependabotTestFile(t, repoDir, manifest, "")
			vars, err := DependabotEcosystemVars(repoDir, nil)
			if err != nil {
				t.Fatal(err)
			}
			if vars["DEPENDABOT_PIP_ENABLED"] != "1" {
				t.Fatalf("DEPENDABOT_PIP_ENABLED = %q, want 1", vars["DEPENDABOT_PIP_ENABLED"])
			}
		})
	}
	for _, manifest := range []string{
		filepath.Join("sub", "pyproject.toml"),
		filepath.Join("sub", "setup.py"),
		filepath.Join("sub", "setup.cfg"),
		filepath.Join("sub", "Pipfile"),
	} {
		t.Run(manifest+" alone does not enable pip", func(t *testing.T) {
			repoDir := t.TempDir()
			writeDependabotTestFile(t, repoDir, manifest, "")
			vars, err := DependabotEcosystemVars(repoDir, nil)
			if !errors.Is(err, errNoDependabotEcosystems) {
				t.Fatalf("error = %v, want errNoDependabotEcosystems", err)
			}
			if vars["DEPENDABOT_PIP_ENABLED"] == "1" {
				t.Fatalf("DEPENDABOT_PIP_ENABLED = %q, want pip off", vars["DEPENDABOT_PIP_ENABLED"])
			}
		})
	}
	t.Run("requirements directory file enables pip alongside npm", func(t *testing.T) {
		repoDir := t.TempDir()
		writeDependabotTestFile(t, repoDir, filepath.Join("requirements", "dev.txt"), "")
		writeDependabotTestFile(t, repoDir, "package.json", "{}")
		vars, err := DependabotEcosystemVars(repoDir, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"DEPENDABOT_PIP_ENABLED", "DEPENDABOT_NPM_ENABLED"} {
			if vars[key] != "1" {
				t.Errorf("%s = %q, want 1", key, vars[key])
			}
		}
	})
}

func TestDependabotMixedRepoKeepsPipEnabled(t *testing.T) {
	repoDir := t.TempDir()
	writeDependabotTestFile(t, repoDir, "package.json", "{}")
	writeDependabotTestFile(t, repoDir, "setup.cfg", "")

	vars, err := DependabotEcosystemVars(repoDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"DEPENDABOT_NPM_ENABLED", "DEPENDABOT_PIP_ENABLED"} {
		if vars[key] != "1" {
			t.Errorf("%s = %q, want 1", key, vars[key])
		}
	}
}

func TestDependabotIgnoresUnrelatedTextFiles(t *testing.T) {
	repoDir := t.TempDir()
	writeDependabotTestFile(t, repoDir, "notes.txt", "")

	vars, err := DependabotEcosystemVars(repoDir, nil)
	if !errors.Is(err, errNoDependabotEcosystems) {
		t.Fatalf("error = %v, want errNoDependabotEcosystems", err)
	}
	if vars["DEPENDABOT_PIP_ENABLED"] == "1" {
		t.Fatal("notes.txt must not count as a pip manifest")
	}
}

func TestDependabotKeepsFullTemplateWhenRepoInspectionFails(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	notARepo := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(notARepo, []byte("file"), 0o644); err != nil {
		t.Fatal(err)
	}

	vars, err := DependabotVarsForRepo(notARepo, cfg.Variables, nil)
	if err == nil {
		t.Fatal("expected repository inspection to fail")
	}
	got := renderDependabotTemplate(t, cfg, vars)
	want := renderDependabotTemplate(t, cfg, cfg.Variables)
	if !bytes.Equal(got, want) {
		t.Fatalf("inspection failure did not preserve full template\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestDependabotDetectionFailureAppliesDirectoryLists keeps a bare pinned
// directory as a list even when detection fails and the full template is
// returned, so the template never renders a scalar `directories:`.
func TestDependabotDetectionFailureAppliesDirectoryLists(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	notARepo := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(notARepo, []byte("file"), 0o644); err != nil {
		t.Fatal(err)
	}

	vars, err := DependabotVarsForRepo(notARepo, cfg.Variables, map[string]string{
		"DEPENDABOT_GOMOD_DIRECTORY": "/sub",
	})
	if err == nil {
		t.Fatal("expected repository inspection to fail")
	}
	if got := vars["DEPENDABOT_GOMOD_DIRECTORY"]; got != `["/sub"]` {
		t.Fatalf("DEPENDABOT_GOMOD_DIRECTORY = %q, want [\"/sub\"]", got)
	}
}

// TestDependabotVarsForRepoAppliesDirectoryLists writes a bare pinned
// directory as a list whether detection finds nothing or finds the ecosystem.
func TestDependabotVarsForRepoAppliesDirectoryLists(t *testing.T) {
	pin := map[string]string{"DEPENDABOT_GOMOD_DIRECTORY": "/svc"}
	vars, err := DependabotVarsForRepo(t.TempDir(), pin, nil)
	if !errors.Is(err, errNoDependabotEcosystems) || vars["DEPENDABOT_GOMOD_DIRECTORY"] != `["/svc"]` {
		t.Fatalf("no detection: vars = %v, err = %v; want [\"/svc\"] and errNoDependabotEcosystems", vars, err)
	}
	repoDir := t.TempDir()
	writeDependabotTestFile(t, repoDir, filepath.Join("svc", "go.mod"), "")
	vars, err = DependabotVarsForRepo(repoDir, pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if vars["DEPENDABOT_GOMOD_DIRECTORY"] != `["/svc"]` || vars["DEPENDABOT_GOMOD_ENABLED"] != "1" {
		t.Fatalf("detected: vars = %v, want gomod enabled at [\"/svc\"]", vars)
	}
}

func TestDependabotNoDetectionKeepsFullNonEmptyTemplate(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	repoDir := t.TempDir()

	vars, err := DependabotVarsForRepo(repoDir, cfg.Variables, nil)
	if !errors.Is(err, errNoDependabotEcosystems) {
		t.Fatalf("error = %v, want errNoDependabotEcosystems", err)
	}
	got := renderDependabotTemplate(t, cfg, vars)
	want := renderDependabotTemplate(t, cfg, cfg.Variables)
	if !bytes.Equal(got, want) {
		t.Fatalf("no-detection did not preserve full template\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	var doc struct {
		Updates []map[string]any `yaml:"updates"`
	}
	if err := yaml.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Updates) == 0 {
		t.Fatalf("updates is not a non-empty YAML sequence\n%s", got)
	}
}

func TestDependabotRejectsEscapingDirectories(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		relative string
		outside  string
		symlink  bool
	}{
		{name: "parent traversal", relative: "../x", outside: "x"},
		{name: "nested parent traversal", relative: "a/../../b", outside: "b"},
		{name: "symlink escape", relative: "link", outside: "outside", symlink: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			base := t.TempDir()
			repoDir := filepath.Join(base, "repo")
			if err := os.MkdirAll(repoDir, 0o755); err != nil {
				t.Fatal(err)
			}
			outsideDir := filepath.Join(base, testCase.outside)
			if err := os.MkdirAll(outsideDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if testCase.symlink {
				if err := os.Symlink(outsideDir, filepath.Join(repoDir, "link")); err != nil {
					t.Fatal(err)
				}
			}

			repoRoot, err := filepath.EvalSymlinks(repoDir)
			if err != nil {
				t.Fatal(err)
			}
			if dirs, err := expandDependabotDirectory(repoRoot, testCase.relative); err == nil {
				t.Fatalf("expandDependabotDirectory(%q) = %q, want error", testCase.relative, dirs)
			}

			vars, err := DependabotEcosystemVars(repoDir, map[string]string{
				"DEPENDABOT_GOMOD_DIRECTORY": testCase.relative,
			})
			if err != nil {
				t.Fatal(err)
			}
			if vars["DEPENDABOT_GOMOD_ENABLED"] != "1" {
				t.Errorf("DEPENDABOT_GOMOD_ENABLED = %q, want 1 (safe fallback)", vars["DEPENDABOT_GOMOD_ENABLED"])
			}
			if vars["DEPENDABOT_NPM_ENABLED"] != "0" {
				t.Errorf("DEPENDABOT_NPM_ENABLED = %q, want 0 (per-ecosystem detection)", vars["DEPENDABOT_NPM_ENABLED"])
			}
		})
	}
}

func TestDependabotActionsDetection(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		files       []string
		directories string
		want        string
	}{
		{
			name:        "workflow yml at repository root",
			files:       []string{filepath.Join(".github", "workflows", "ci.yml")},
			directories: `["/"]`,
			want:        "1",
		},
		{
			name:        "workflow yaml at repository root",
			files:       []string{filepath.Join(".github", "workflows", "ci.yaml")},
			directories: `["/"]`,
			want:        "1",
		},
		{
			name:        "action yml at repository root without workflows",
			files:       []string{"action.yml"},
			directories: `["/"]`,
			want:        "1",
		},
		{
			name:        "action yaml at repository root without workflows",
			files:       []string{"action.yaml"},
			directories: `["/"]`,
			want:        "1",
		},
		{
			name:        "action yml matched by glob",
			files:       []string{filepath.Join(".github", "actions", "build", "action.yml")},
			directories: `["/", ".github/actions/*"]`,
			want:        "1",
		},
		{
			name:        "action yaml in explicit directory",
			files:       []string{filepath.Join(".github", "actions", "build", "action.yaml")},
			directories: `["/", ".github/actions/build"]`,
			want:        "1",
		},
		{
			name:        "any yml in non-root explicit directory",
			files:       []string{filepath.Join(".github", "actions", "build", "ci.yml")},
			directories: `[".github/actions/build"]`,
			want:        "1",
		},
		{
			name:        "any yaml in non-root globbed directory",
			files:       []string{filepath.Join(".github", "actions", "build", "ci.yaml")},
			directories: `[".github/actions/*"]`,
			want:        "1",
		},
		{
			name:        "root arbitrary yml is not an action",
			files:       []string{"docker-compose.yml"},
			directories: `["/"]`,
			want:        "0",
		},
		{
			name:        "no workflow or action manifests",
			files:       []string{filepath.Join(".github", "workflows", "README.md")},
			directories: `["/", ".github/actions/*"]`,
			want:        "0",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			repoDir := t.TempDir()
			writeDependabotTestFile(t, repoDir, "go.mod", "")
			for _, file := range testCase.files {
				writeDependabotTestFile(t, repoDir, file, "")
			}

			vars, err := DependabotEcosystemVars(repoDir, map[string]string{
				"DEPENDABOT_ACTIONS_DIRECTORIES": testCase.directories,
			})
			if err != nil {
				t.Fatal(err)
			}
			if vars["DEPENDABOT_ACTIONS_ENABLED"] != testCase.want {
				t.Errorf("DEPENDABOT_ACTIONS_ENABLED = %q, want %q", vars["DEPENDABOT_ACTIONS_ENABLED"], testCase.want)
			}
		})
	}
}

func TestDependabotMissingDirectoryIsAbsent(t *testing.T) {
	repoDir := t.TempDir()
	writeDependabotTestFile(t, repoDir, "package.json", "{}")
	writeDependabotTestFile(t, repoDir, "blocked", "")

	vars, err := DependabotEcosystemVars(repoDir, map[string]string{
		"DEPENDABOT_GOMOD_DIRECTORY": "blocked/sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	if vars["DEPENDABOT_GOMOD_ENABLED"] != "0" {
		t.Errorf("DEPENDABOT_GOMOD_ENABLED = %q, want 0 for ENOTDIR", vars["DEPENDABOT_GOMOD_ENABLED"])
	}
	if vars["DEPENDABOT_NPM_ENABLED"] != "1" {
		t.Errorf("DEPENDABOT_NPM_ENABLED = %q, want 1", vars["DEPENDABOT_NPM_ENABLED"])
	}
}

func TestDependabotEnabledVarsAreNotOverridable(t *testing.T) {
	repoDir := t.TempDir()
	writeDependabotTestFile(t, repoDir, "go.mod", "")

	vars, err := DependabotVarsForRepo(repoDir, nil, map[string]string{
		"DEPENDABOT_GOMOD_ENABLED": "0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if vars["DEPENDABOT_GOMOD_ENABLED"] != "1" {
		t.Errorf("DEPENDABOT_GOMOD_ENABLED = %q, want 1 (not overridable)", vars["DEPENDABOT_GOMOD_ENABLED"])
	}
}

func loadDependabotTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.LoadConfig(filepath.Join("..", "..", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func renderDependabotTemplate(t *testing.T, cfg *config.Config, vars map[string]string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "templates", "dependabot.yml"))
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := ProcessTemplate(raw, vars, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rendered
}

func renderedDependabotEcosystems(t *testing.T, raw []byte) string {
	t.Helper()
	var doc struct {
		Updates []struct {
			Ecosystem string `yaml:"package-ecosystem"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	ecosystems := make([]string, 0, len(doc.Updates))
	for _, update := range doc.Updates {
		ecosystems = append(ecosystems, update.Ecosystem)
	}
	return strings.Join(ecosystems, ",")
}

func writeDependabotTestFile(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestListDirectoriesMatchesTemplate(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "templates", "dependabot.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ecosystem := range dependabotEcosystems {
		rendersList := strings.Contains(string(raw), `directories: "{{ .`+ecosystem.directoriesVar+` }}"`)
		if rendersList != ecosystem.listDirectories {
			t.Errorf("%s: template renders a directories list = %v, listDirectories = %v", ecosystem.name, rendersList, ecosystem.listDirectories)
		}
	}
}

// Manifest detection can disable every block before the first enabled one.
// Prettier rejects a blank line between updates: and that first list entry.
func TestDependabotFirstEnabledEcosystemFormatting(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	for _, first := range dependabotEcosystems {
		t.Run(first.name, func(t *testing.T) {
			vars := map[string]string{}
			for key, value := range cfg.Variables {
				vars[key] = value
			}
			for _, ecosystem := range dependabotEcosystems {
				vars[ecosystem.enabledVar] = "0"
			}
			vars[first.enabledVar] = "1"
			rendered := renderDependabotTemplate(t, cfg, vars)
			if !strings.Contains(string(rendered), "updates:\n  - package-ecosystem:") {
				t.Fatalf("first update must immediately follow updates:\n%s", rendered)
			}
		})
	}
}
