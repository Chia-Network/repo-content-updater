package repo

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/chia-network/repo-content-updater/internal/config"
)

func TestApplySelection(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	templates, err := filepath.Abs(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	content := &Content{templates: templates}
	marker := "# " + cfg.GetFileInfo("dependabot-actions").AdoptionMarker
	actionsOnly := "# managed by the repo-content-updater\n" + marker + "\nversion: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n"
	workflow := filepath.Join(".github", "workflows", "ci.yml")
	dependabotOnly := config.ManagedFileSelection{Defaults: []config.DefaultBundle{{Root: "dependabot-actions", Files: []string{"dependabot-actions"}}}}

	apply := func(t *testing.T, repoName string, selection config.ManagedFileSelection) ([]string, error) {
		t.Helper()
		var staged []string
		err := content.applySelection(repoName, selection, cfg, Config{}, func(file string, repoPaths []string) error {
			staged = append(staged, file)
			return nil
		})
		return staged, err
	}
	readDependabot := func(t *testing.T, repoName string) string {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(repoDir(repoName), ".github", "dependabot.yml"))
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}

	t.Run("an unmarked dependabot.yml is left byte for byte", func(t *testing.T) {
		repoName := "unmarked"
		original := "version: 2\nupdates: []\n"
		writeDependabotTestFile(t, repoDir(repoName), ".github/dependabot.yml", original)
		writeDependabotTestFile(t, repoDir(repoName), "go.mod", "")
		writeDependabotTestFile(t, repoDir(repoName), workflow, "")
		staged, err := apply(t, repoName, dependabotOnly)
		if err != nil {
			t.Fatal(err)
		}
		if len(staged) != 0 || readDependabot(t, repoName) != original {
			t.Fatalf("staged %v; file changed to:\n%s", staged, readDependabot(t, repoName))
		}
	})

	t.Run("a marked actions-only file gains detected ecosystems", func(t *testing.T) {
		repoName := "marked-go"
		writeDependabotTestFile(t, repoDir(repoName), ".github/dependabot.yml", actionsOnly)
		writeDependabotTestFile(t, repoDir(repoName), "go.mod", "")
		writeDependabotTestFile(t, repoDir(repoName), workflow, "")
		if _, err := apply(t, repoName, dependabotOnly); err != nil {
			t.Fatal(err)
		}
		body := readDependabot(t, repoName)
		if got := renderedDependabotEcosystems(t, []byte(body)); got != "gomod,github-actions" {
			t.Fatalf("ecosystems = %q, want gomod,github-actions\n%s", got, body)
		}
		if !containsTrimmedLine(body, marker) {
			t.Fatalf("rendered file lost its adoption marker\n%s", body)
		}
	})

	t.Run("the default actions policy is weekly with the shared reviewers", func(t *testing.T) {
		repoName := "marked-actions"
		writeDependabotTestFile(t, repoDir(repoName), ".github/dependabot.yml", actionsOnly)
		writeDependabotTestFile(t, repoDir(repoName), workflow, "")
		if _, err := apply(t, repoName, dependabotOnly); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Updates []struct {
				Ecosystem   string            `yaml:"package-ecosystem"`
				Directories []string          `yaml:"directories"`
				Schedule    map[string]string `yaml:"schedule"`
				Reviewers   []string          `yaml:"reviewers"`
				Groups      map[string]any    `yaml:"groups"`
			} `yaml:"updates"`
		}
		if err := yaml.Unmarshal([]byte(readDependabot(t, repoName)), &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Updates) != 1 {
			t.Fatalf("updates = %#v, want github-actions only", doc.Updates)
		}
		got := doc.Updates[0]
		if got.Ecosystem != "github-actions" ||
			!reflect.DeepEqual(got.Schedule, map[string]string{"interval": "weekly", "day": "tuesday"}) ||
			!reflect.DeepEqual(got.Reviewers, []string{"cameroncooper", "emlowe"}) ||
			got.Groups != nil {
			t.Fatalf("actions policy = %#v, want weekly on tuesday, reviewers cameroncooper and emlowe, ungrouped", got)
		}
	})

	t.Run("a detection error leaves the adopted file in place", func(t *testing.T) {
		repoName := "detect-error"
		writeDependabotTestFile(t, repoDir(repoName), ".github/dependabot.yml", actionsOnly)
		writeDependabotTestFile(t, repoDir(repoName), workflow, "")
		locked := filepath.Join(repoDir(repoName), "locked")
		if err := os.Mkdir(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
		if _, err := os.ReadDir(locked); err == nil {
			t.Skip("directory permissions are not enforced for this user")
		}
		staged, err := apply(t, repoName, dependabotOnly)
		if err != nil {
			t.Fatal(err)
		}
		if len(staged) != 0 || readDependabot(t, repoName) != actionsOnly {
			t.Fatalf("staged %v; file changed to:\n%s", staged, readDependabot(t, repoName))
		}
	})

	t.Run("alternate cleanup never leaves the checkout", func(t *testing.T) {
		repoName := "linked-github"
		outside := t.TempDir()
		outsideFile := filepath.Join(outside, "dependabot.yaml")
		if err := os.WriteFile(outsideFile, []byte("keep\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		writeDependabotTestFile(t, repoDir(repoName), "go.mod", "")
		if err := os.Symlink(outside, filepath.Join(repoDir(repoName), ".github")); err != nil {
			t.Fatal(err)
		}
		if _, err := apply(t, repoName, config.ManagedFileSelection{Explicit: []string{"dependabot"}}); err == nil {
			t.Fatal("expected an error for a linked .github directory")
		}
		if body, err := os.ReadFile(outsideFile); err != nil || string(body) != "keep\n" {
			t.Fatalf("outside file = %q, %v; want it unchanged", body, err)
		}
	})
}

func TestApplySelectionChecksEveryPathBeforeWriting(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	templates, err := filepath.Abs(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	repoName := "linked-workflows"
	writeDependabotTestFile(t, repoDir(repoName), "go.mod", "")
	if err := os.MkdirAll(filepath.Join(repoDir(repoName), ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(repoDir(repoName), ".github", "workflows")); err != nil {
		t.Fatal(err)
	}
	selection := config.ManagedFileSelection{Explicit: []string{"dependabot", "dependency-cursor-review"}}
	err = (&Content{templates: templates}).applySelection(repoName, selection, cfg, Config{}, func(string, []string) error { return nil })
	if err == nil {
		t.Fatal("expected an error for a linked workflows directory")
	}
	if _, err := os.Lstat(filepath.Join(repoDir(repoName), ".github", "dependabot.yml")); !os.IsNotExist(err) {
		t.Fatalf("dependabot.yml was written before the failing path was checked: %v", err)
	}
}

func TestLoadRepoConfigReadsOnlyRegularFiles(t *testing.T) {
	repo := t.TempDir()
	outside := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(outside, []byte("var_overrides:\n  X: outside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(repo, ".repo-content-updater.yaml")); err != nil {
		t.Fatal(err)
	}
	writeDependabotTestFile(t, repo, ".repo-content-updater.yml", "var_overrides:\n  X: inside\n")
	got, err := (&Content{}).LoadRepoConfig(repo)
	if err != nil {
		t.Fatal(err)
	}
	if got.VarOverrides["X"] != "inside" {
		t.Fatalf("overrides = %v, want the in-repo .yml", got.VarOverrides)
	}
}

func TestAdoptionStaysInsideTheCheckout(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	fileinfo := cfg.GetFileInfo("dependabot-actions")
	repo := t.TempDir()
	outside := t.TempDir()
	writeDependabotTestFile(t, outside, "dependabot.yml", "# "+fileinfo.AdoptionMarker+"\n")
	writeDependabotTestFile(t, outside, filepath.Join("workflows", "ci.yml"), "")
	if err := os.Symlink(outside, filepath.Join(repo, ".github")); err != nil {
		t.Fatal(err)
	}

	state, err := existingFileState(repo, fileinfo)
	if err != nil {
		t.Fatal(err)
	}
	if state == fileMarked {
		t.Fatal("a marked file outside the checkout made the default owned")
	}
	if ok, err := requiredPathExists(repo, ".github/workflows"); err != nil || ok {
		t.Fatalf("requiredPathExists through a linked .github = %v, %v; want false", ok, err)
	}

	linkedWorkflows := t.TempDir()
	if err := os.MkdirAll(filepath.Join(linkedWorkflows, ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "workflows"), filepath.Join(linkedWorkflows, ".github", "workflows")); err != nil {
		t.Fatal(err)
	}
	if ok, err := requiredPathExists(linkedWorkflows, ".github/workflows"); err != nil || ok {
		t.Fatalf("requiredPathExists for a linked workflows directory = %v, %v; want false", ok, err)
	}
	if occupied, err := anyPathExists(repo, fileinfo); err != nil || !occupied {
		t.Fatalf("anyPathExists below a linked parent = %v, %v; want occupied", occupied, err)
	}
}

func TestDefaultDependabotDiscoversNestedManifests(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	workflow := filepath.Join(".github", "workflows", "ci.yml")
	tests := []struct {
		name      string
		manifests []string
		want      string
		dirs      map[string][]string
	}{
		{
			name:      "dockerfiles in two services",
			manifests: []string{"services/api/Dockerfile", "web/Dockerfile"},
			want:      "github-actions,docker",
			dirs:      map[string][]string{"docker": {"/services/api", "/web"}},
		},
		{
			name:      "terraform below the root",
			manifests: []string{"infra/main.tf"},
			want:      "github-actions,terraform",
			dirs:      map[string][]string{"terraform": {"/infra"}},
		},
		{
			name:      "nuget project without a root solution",
			manifests: []string{"src/App/App.csproj"},
			want:      "github-actions,nuget",
			dirs:      map[string][]string{"nuget": {"/src/App"}},
		},
		{
			name:      "a root solution covers nested projects",
			manifests: []string{"App.sln", "src/App/App.csproj"},
			want:      "github-actions,nuget",
			dirs:      map[string][]string{"nuget": {"/"}},
		},
		{
			name:      "unusual directory names stay one list entry each",
			manifests: []string{"a \"b\" #c: d/Dockerfile", "e\nf/Dockerfile"},
			want:      "github-actions,docker",
			dirs:      map[string][]string{"docker": {"/a \"b\" #c: d", "/e\nf"}},
		},
		{name: "containerfile only stays off", manifests: []string{"Containerfile"}, want: "github-actions"},
		{name: "vendored dockerfiles are ignored", manifests: []string{"node_modules/pkg/Dockerfile"}, want: "github-actions"},
		{name: "workflows and a root go.mod", manifests: []string{"go.mod"}, want: "gomod,github-actions"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := t.TempDir()
			writeDependabotTestFile(t, repo, workflow, "")
			for _, manifest := range tt.manifests {
				writeDependabotTestFile(t, repo, filepath.FromSlash(manifest), "")
			}
			vars, err := DependabotVarsForRepo(repo, cfg.Variables, nil)
			if err != nil {
				t.Fatal(err)
			}
			rendered := renderDependabotTemplate(t, cfg, vars)
			if got := renderedDependabotEcosystems(t, rendered); got != tt.want {
				t.Fatalf("ecosystems = %q, want %q\n%s", got, tt.want, rendered)
			}
			for ecosystem, want := range tt.dirs {
				if got := renderedDependabotDirectories(t, rendered, ecosystem); !reflect.DeepEqual(got, want) {
					t.Fatalf("%s directories = %v, want %v", ecosystem, got, want)
				}
			}
		})
	}

	listEcosystems := []struct{ ecosystem, directoriesVar, manifest string }{
		{"github-actions", "DEPENDABOT_ACTIONS_DIRECTORIES", "action.yml"},
		{"docker", "DEPENDABOT_DOCKER_DIRECTORIES", "Dockerfile"},
		{"terraform", "DEPENDABOT_TERRAFORM_DIRECTORIES", "main.tf"},
		{"nuget", "DEPENDABOT_NUGET_DIRECTORIES", "App.csproj"},
	}
	for _, tc := range listEcosystems {
		for _, pin := range []string{`["/pinned"]`, "/pinned", " /pinned "} {
			t.Run(tc.ecosystem+" pinned directories "+pin+" render as a list", func(t *testing.T) {
				repo := t.TempDir()
				writeDependabotTestFile(t, repo, filepath.Join("pinned", tc.manifest), "")
				writeDependabotTestFile(t, repo, filepath.Join("other", tc.manifest), "")
				vars, err := DependabotVarsForRepo(repo, cfg.Variables, map[string]string{tc.directoriesVar: pin})
				if err != nil {
					t.Fatal(err)
				}
				rendered := renderDependabotTemplate(t, cfg, vars)
				if got := renderedDependabotDirectories(t, rendered, tc.ecosystem); !reflect.DeepEqual(got, []string{"/pinned"}) {
					t.Fatalf("%s directories = %v, want [/pinned]\n%s", tc.ecosystem, got, rendered)
				}
			})
		}
	}
}

func renderedDependabotDirectories(t *testing.T, raw []byte, ecosystem string) []string {
	t.Helper()
	var doc struct {
		Updates []struct {
			Ecosystem   string   `yaml:"package-ecosystem"`
			Directories []string `yaml:"directories"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, update := range doc.Updates {
		if update.Ecosystem == ecosystem {
			return update.Directories
		}
	}
	t.Fatalf("no %s update in\n%s", ecosystem, strings.TrimSpace(string(raw)))
	return nil
}
