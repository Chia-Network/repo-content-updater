package repo

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-github/v59/github"

	"github.com/chia-network/repo-content-updater/internal/config"
)

func TestTemplateInputsForFile(t *testing.T) {
	t.Chdir(t.TempDir())
	repoName := "wiring"
	writeDependabotTestFile(t, repoDir(repoName), filepath.Join("pkg", "nested", "requirements.txt"), "")
	writeDependabotTestFile(t, repoDir(repoName), "package.json", "{}")

	cfg := &config.Config{Variables: map[string]string{
		"BASE_VAR":                 "base",
		"DEPENDABOT_PIP_DIRECTORY": "/",
	}}
	repoConfig := Config{VarOverrides: map[string]string{
		"DEPENDABOT_PIP_DIRECTORY": "pkg/nested",
		"OVERRIDE_VAR":             "override",
	}}

	t.Run("dependabot merges overrides and detects flags", func(t *testing.T) {
		fileinfo := &config.File{Name: "dependabot", TemplateName: dependabotTemplateName}
		vars, overrides, err := templateInputsForFile(fileinfo, repoName, cfg, repoConfig)
		if err != nil {
			t.Fatal(err)
		}
		if overrides != nil {
			t.Fatalf("overrides = %#v, want nil", overrides)
		}
		for key, want := range map[string]string{
			"BASE_VAR":                 "base",
			"OVERRIDE_VAR":             "override",
			"DEPENDABOT_PIP_DIRECTORY": `["pkg/nested"]`,
			"DEPENDABOT_PIP_ENABLED":   "1",
			"DEPENDABOT_NPM_ENABLED":   "1",
		} {
			if got := vars[key]; got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
	})

	t.Run("other templates keep configured inputs unchanged", func(t *testing.T) {
		fileinfo := &config.File{Name: "license", TemplateName: "LICENSE"}
		vars, overrides, err := templateInputsForFile(fileinfo, repoName, cfg, repoConfig)
		if err != nil {
			t.Fatal(err)
		}
		if !maps.Equal(vars, cfg.Variables) {
			t.Errorf("vars = %#v, want cfg.Variables %#v", vars, cfg.Variables)
		}
		if !maps.Equal(overrides, repoConfig.VarOverrides) {
			t.Errorf("overrides = %#v, want repo overrides %#v", overrides, repoConfig.VarOverrides)
		}
		if _, ok := vars["DEPENDABOT_PIP_ENABLED"]; ok {
			t.Error("non-Dependabot template should not receive detected flags")
		}
	})
}

func TestExistingFileState(t *testing.T) {
	dir := t.TempDir()
	fileinfo := &config.File{
		RepoPath:                ".github/dependabot.yml",
		AlternatePaths:          []string{".github/dependabot.yaml"},
		AdoptionMarker:          "repo-content-updater:dependabot",
		PreviousAdoptionMarkers: []string{"repo-content-updater:dependabot-actions"},
	}
	markerLine := "# " + fileinfo.AdoptionMarker
	previousMarkerLine := "# " + fileinfo.PreviousAdoptionMarkers[0]
	fullManaged := "# This file is managed by the repo-content-updater project.\nversion: 2\n"
	unmarked := *fileinfo
	unmarked.AdoptionMarker = ""

	tests := []struct {
		name     string
		fileinfo *config.File
		files    map[string]string
		want     fileState
	}{
		{name: "absent", fileinfo: fileinfo, want: fileAbsent},
		{name: "unmarked", fileinfo: fileinfo, files: map[string]string{fileinfo.RepoPath: "version: 2\n"}, want: fileUnowned},
		{name: "generic managed marker only", fileinfo: fileinfo, files: map[string]string{fileinfo.RepoPath: fullManaged}, want: fileUnowned},
		{name: "marked", fileinfo: fileinfo, files: map[string]string{fileinfo.RepoPath: markerLine + "\nversion: 2\n"}, want: fileMarked},
		{name: "marked previous", fileinfo: fileinfo, files: map[string]string{fileinfo.RepoPath: previousMarkerLine + "\nversion: 2\n"}, want: fileMarked},
		{name: "marked alternate", fileinfo: fileinfo, files: map[string]string{fileinfo.AlternatePaths[0]: "  " + markerLine + "  \n"}, want: fileMarked},
		{name: "unmarked alternate beside marked", fileinfo: fileinfo, files: map[string]string{fileinfo.RepoPath: markerLine + "\n", fileinfo.AlternatePaths[0]: "version: 2\n"}, want: fileUnowned},
		{name: "no marker absent", fileinfo: &unmarked, want: fileAbsent},
		{name: "no marker existing", fileinfo: &unmarked, files: map[string]string{unmarked.RepoPath: markerLine + "\n"}, want: fileUnowned},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := filepath.Join(dir, fmt.Sprint(i))
			for rel, body := range tt.files {
				writeDependabotTestFile(t, root, rel, body)
			}
			got, err := existingFileState(root, tt.fileinfo)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("state = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestAdoptableDefaults covers the adopt-only rules for both default
// bundles as selected from config.yaml.
func TestAdoptableDefaults(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	t.Chdir(t.TempDir())
	workflow := filepath.Join(".github", "workflows", "ci.yml")
	actionsMarker := "# " + cfg.GetFileInfo("dependabot-actions").AdoptionMarker + "\nversion: 2\n"
	reviewMarker := "# " + cfg.GetFileInfo("dependency-cursor-review").AdoptionMarker + "\nname: x\n"
	reviewPath := cfg.GetFileInfo("dependency-cursor-review").RepoPath
	companionPath := cfg.GetFileInfo("upstream-release-checkout").RepoPath

	tests := []struct {
		name    string
		files   map[string]string
		actions bool
		review  bool
	}{
		{name: "nothing", files: map[string]string{"notes.txt": ""}},
		{name: "workflows dir without workflow files", files: map[string]string{".github/workflows/notes.txt": ""}},
		{name: "workflows only", files: map[string]string{workflow: ""}, actions: true, review: true},
		{name: "marked dependabot is upgraded", files: map[string]string{workflow: "", ".github/dependabot.yml": actionsMarker}, actions: true, review: true},
		{name: "marked alternate dependabot is upgraded", files: map[string]string{workflow: "", ".github/dependabot.yaml": actionsMarker}, actions: true, review: true},
		{name: "unmarked dependabot is left alone", files: map[string]string{workflow: "", ".github/dependabot.yml": "version: 2\n"}, review: true},
		{name: "unmarked review workflow is left alone", files: map[string]string{workflow: "", reviewPath: "name: x\n"}, actions: true},
		{name: "occupied companion path blocks a new bundle", files: map[string]string{workflow: "", companionPath: "#!/bin/sh\n"}, actions: true},
		{name: "owned bundle updates existing companions", files: map[string]string{workflow: "", reviewPath: reviewMarker, companionPath: "#!/bin/sh\n"}, actions: true, review: true},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoName := fmt.Sprintf("repo-%d", i)
			for rel, body := range tt.files {
				writeDependabotTestFile(t, repoDir(repoName), rel, body)
			}
			selection := filesForRepo(cfg.ResolveManagedFileSelection(repoName, nil), &github.Repository{})
			files, err := adoptableDefaults(repoName, selection.Defaults, cfg)
			if err != nil {
				t.Fatal(err)
			}
			adopted := map[string]bool{}
			for _, file := range files {
				if file.Origin != config.OriginDefault {
					t.Fatalf("%s origin = %d, want default", file.Name, file.Origin)
				}
				adopted[file.Name] = true
			}
			if adopted["dependabot-actions"] != tt.actions || adopted["dependency-cursor-review"] != tt.review {
				t.Fatalf("adopted = %v, want dependabot-actions=%v dependency-cursor-review=%v", adopted, tt.actions, tt.review)
			}
		})
	}
}

// TestDefaultDependabotRendersDetectedEcosystems renders the default through
// the same manifest detection as the explicit dependabot file.
func TestDefaultDependabotRendersDetectedEcosystems(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	templates, err := filepath.Abs(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	content := &Content{templates: templates}
	fileinfo := cfg.GetFileInfo("dependabot-actions")
	asDefault := config.SelectedFile{Name: fileinfo.Name, Origin: config.OriginDefault}
	workflow := filepath.Join(".github", "workflows", "ci.yml")

	tests := []struct {
		name      string
		manifests []string
		overrides map[string]string
		want      string
	}{
		{name: "workflows only", want: "github-actions"},
		{name: "go", manifests: []string{"go.mod"}, want: "gomod,github-actions"},
		{name: "python", manifests: []string{"pyproject.toml"}, want: "pip,github-actions"},
		{name: "node", manifests: []string{"package.json"}, want: "github-actions,npm"},
		{name: "docker", manifests: []string{"Dockerfile"}, want: "github-actions,docker"},
		{name: "terraform", manifests: []string{".terraform.lock.hcl"}, want: "github-actions,terraform"},
		{name: "nuget", manifests: []string{"App.csproj"}, want: "github-actions,nuget"},
		{
			name:      "override directory",
			manifests: []string{filepath.Join("svc", "go.mod")},
			overrides: map[string]string{"DEPENDABOT_GOMOD_DIRECTORY": "svc"},
			want:      "gomod,github-actions",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoName := strings.ReplaceAll(tt.name, " ", "-")
			writeDependabotTestFile(t, repoDir(repoName), workflow, "")
			for _, manifest := range tt.manifests {
				writeDependabotTestFile(t, repoDir(repoName), manifest, "")
			}
			rendered, err := content.renderManagedFile(repoName, asDefault, fileinfo, cfg, Config{VarOverrides: tt.overrides})
			if err != nil {
				t.Fatal(err)
			}
			if got := renderedDependabotEcosystems(t, rendered); got != tt.want {
				t.Fatalf("ecosystems = %q, want %q\n%s", got, tt.want, rendered)
			}
			if !containsTrimmedLine(string(rendered), "# "+fileinfo.AdoptionMarker) {
				t.Fatalf("rendered default lost its adoption marker\n%s", rendered)
			}
		})
	}

	t.Run("an ecosystem detection error keeps that ecosystem", func(t *testing.T) {
		repoName := "ecosystem-error"
		writeDependabotTestFile(t, repoDir(repoName), workflow, "")
		overrides := map[string]string{"DEPENDABOT_GOMOD_DIRECTORY": "../outside"}
		rendered, err := content.renderManagedFile(repoName, asDefault, fileinfo, cfg, Config{VarOverrides: overrides})
		if err != nil {
			t.Fatal(err)
		}
		if got := renderedDependabotEcosystems(t, rendered); got != "gomod,github-actions" {
			t.Fatalf("ecosystems = %q, want gomod,github-actions", got)
		}
	})

	t.Run("a repository detection error skips the default", func(t *testing.T) {
		rendered, err := content.renderManagedFile("missing-repo", asDefault, fileinfo, cfg, Config{})
		if !errors.Is(err, errSkipManagedFile) || rendered != nil {
			t.Fatalf("render = %q, %v; want a skip", rendered, err)
		}
	})

	t.Run("a repository detection error keeps the full explicit configuration", func(t *testing.T) {
		explicit := cfg.GetFileInfo("dependabot")
		rendered, err := content.renderManagedFile("missing-repo", config.SelectedFile{Name: explicit.Name}, explicit, cfg, Config{})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := renderedDependabotEcosystems(t, rendered), "gomod,pip,github-actions,npm,cargo,swift,docker,terraform,nuget"; got != want {
			t.Fatalf("ecosystems = %q, want %q", got, want)
		}
	})

	t.Run("explicit dependabot renders without the adoption marker", func(t *testing.T) {
		repoName := "explicit"
		writeDependabotTestFile(t, repoDir(repoName), "go.mod", "")
		rendered, err := content.renderManagedFile(repoName, config.SelectedFile{Name: "dependabot"}, cfg.GetFileInfo("dependabot"), cfg, Config{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(rendered), "repo-content-updater:") {
			t.Fatalf("explicit dependabot carries an adoption marker\n%s", rendered)
		}
		if got := renderedDependabotEcosystems(t, rendered); got != "gomod" {
			t.Fatalf("ecosystems = %q, want gomod", got)
		}
	})
}

func TestFilesForRepo(t *testing.T) {
	defaultActions := config.DefaultBundle{Root: "dependabot-actions", Files: []string{"dependabot-actions"}}
	selection := config.ManagedFileSelection{
		Explicit: []string{"dep-review"},
		Defaults: []config.DefaultBundle{defaultActions},
	}
	wantBoth := selection
	wantExplicit := config.ManagedFileSelection{Explicit: selection.Explicit}
	defaultsOnly := config.ManagedFileSelection{Defaults: selection.Defaults}

	tests := []struct {
		name      string
		selection config.ManagedFileSelection
		repo      *github.Repository
		want      config.ManagedFileSelection
	}{
		{name: "defaults apply to a normal repo", selection: selection, repo: &github.Repository{}, want: wantBoth},
		{name: "explicit files still apply to archived repos", selection: selection, repo: &github.Repository{Archived: github.Bool(true)}, want: wantExplicit},
		{name: "archived repos without explicit files get nothing", selection: defaultsOnly, repo: &github.Repository{Archived: github.Bool(true)}},
		{name: "explicit files still apply to forks", selection: selection, repo: &github.Repository{Fork: github.Bool(true)}, want: wantExplicit},
		{name: "forks without explicit files get nothing", selection: defaultsOnly, repo: &github.Repository{Fork: github.Bool(true)}},
		{name: "private suffix", selection: selection, repo: &github.Repository{Name: github.String("chiavdf-private")}, want: wantExplicit},
		{name: "private prefix", selection: selection, repo: &github.Repository{Name: github.String("private-chiapos")}, want: wantExplicit},
		{name: "dos suffix", selection: selection, repo: &github.Repository{Name: github.String("chiavdf-dos")}, want: wantExplicit},
		{name: "dos suffix any case", selection: selection, repo: &github.Repository{Name: github.String("Chia-DOS")}, want: wantExplicit},
		{name: "dos prefix is eligible", selection: selection, repo: &github.Repository{Name: github.String("dosbox")}, want: wantBoth},
		{name: "defaults apply regardless of repo size", selection: selection, repo: &github.Repository{Size: github.Int(0)}, want: wantBoth},
		{name: "missing metadata keeps explicit files only", selection: selection, want: wantExplicit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := filesForRepo(tt.selection, tt.repo); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("selection = %#v, want %#v", got, tt.want)
			}
		})
	}
}
