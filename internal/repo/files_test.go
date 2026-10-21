package repo

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"slices"
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
			"DEPENDABOT_PIP_DIRECTORY": "pkg/nested",
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

func TestShouldAdoptExistingFile(t *testing.T) {
	t.Chdir(t.TempDir())
	fileinfo := &config.File{
		Name:           "dependabot",
		RepoPath:       ".github/dependabot.yml",
		AlternatePaths: []string{".github/dependabot.yaml"},
	}

	t.Run("creates when absent", func(t *testing.T) {
		adopt, err := shouldAdoptExistingFile("absent", fileinfo)
		if err != nil {
			t.Fatal(err)
		}
		if !adopt {
			t.Fatal("absent file should be adopted")
		}
	})

	t.Run("skips an unmarked existing file", func(t *testing.T) {
		writeDependabotTestFile(t, repoDir("unmarked"), fileinfo.RepoPath, "version: 2\n")
		adopt, err := shouldAdoptExistingFile("unmarked", fileinfo)
		if err != nil {
			t.Fatal(err)
		}
		if adopt {
			t.Fatal("unmarked file should not be adopted")
		}
	})

	t.Run("updates a marked existing file", func(t *testing.T) {
		writeDependabotTestFile(t, repoDir("marked"), fileinfo.RepoPath, "// Managed by the repo-content-updater\nversion: 2\n")
		adopt, err := shouldAdoptExistingFile("marked", fileinfo)
		if err != nil {
			t.Fatal(err)
		}
		if !adopt {
			t.Fatal("marked file should be adopted")
		}
	})

	t.Run("skips an unmarked alternate path", func(t *testing.T) {
		writeDependabotTestFile(t, repoDir("alternate"), fileinfo.AlternatePaths[0], "version: 2\n")
		adopt, err := shouldAdoptExistingFile("alternate", fileinfo)
		if err != nil {
			t.Fatal(err)
		}
		if adopt {
			t.Fatal("unmarked alternate should not be adopted")
		}
	})
}

func TestPrepareManagedFileOrigin(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	templates, err := filepath.Abs(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	content := &Content{templates: templates}
	fileinfo := cfg.GetFileInfo("dependabot")
	if fileinfo == nil {
		t.Fatal("dependabot file missing from config")
	}

	t.Run("default skips when no ecosystem is detected", func(t *testing.T) {
		writeDependabotTestFile(t, repoDir("default-empty"), "notes.txt", "")
		rendered, skip, err := content.prepareManagedFile("default-empty", fileinfo, config.OriginDefault, cfg, Config{})
		if err != nil {
			t.Fatal(err)
		}
		if !skip {
			t.Fatal("default dependabot should be skipped without ecosystems")
		}
		if rendered != nil {
			t.Fatalf("rendered = %q, want nil", rendered)
		}
	})

	t.Run("default skips an unmarked existing file", func(t *testing.T) {
		writeDependabotTestFile(t, repoDir("default-unmarked"), fileinfo.RepoPath, "version: 2\n")
		_, skip, err := content.prepareManagedFile("default-unmarked", fileinfo, config.OriginDefault, cfg, Config{})
		if err != nil {
			t.Fatal(err)
		}
		if !skip {
			t.Fatal("default dependabot should not adopt an unmarked file")
		}
	})

	t.Run("explicit dependabot keeps the full-template fallback", func(t *testing.T) {
		writeDependabotTestFile(t, repoDir("explicit-empty"), "notes.txt", "")
		rendered, skip, err := content.prepareManagedFile("explicit-empty", fileinfo, config.OriginExplicit, cfg, Config{})
		if err != nil {
			t.Fatal(err)
		}
		if skip {
			t.Fatal("explicit dependabot should not be skipped")
		}
		raw, err := os.ReadFile(filepath.Join(templates, "dependabot.yml"))
		if err != nil {
			t.Fatal(err)
		}
		want, err := ProcessTemplate(raw, cfg.Variables, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rendered, want) {
			t.Fatalf("explicit fallback changed\n--- got ---\n%s\n--- want ---\n%s", rendered, want)
		}
	})
}

func TestFilesForRepo(t *testing.T) {
	selection := config.ManagedFileSelection{
		Explicit: []string{"dep-review"},
		Defaults: []string{"dependabot"},
	}
	wantBoth := []config.SelectedFile{
		{Name: "dep-review", Origin: config.OriginExplicit},
		{Name: "dependabot", Origin: config.OriginDefault},
	}
	wantExplicit := []config.SelectedFile{
		{Name: "dep-review", Origin: config.OriginExplicit},
	}

	t.Run("defaults apply to a normal repo", func(t *testing.T) {
		got := filesForRepo(selection, &github.Repository{})
		if !slices.Equal(got, wantBoth) {
			t.Fatalf("files = %#v, want %#v", got, wantBoth)
		}
	})

	t.Run("explicit files still apply to archived repos", func(t *testing.T) {
		got := filesForRepo(selection, &github.Repository{Archived: github.Bool(true)})
		if !slices.Equal(got, wantExplicit) {
			t.Fatalf("files = %#v, want %#v", got, wantExplicit)
		}
	})

	t.Run("archived repos without explicit files get nothing", func(t *testing.T) {
		got := filesForRepo(config.ManagedFileSelection{Defaults: []string{"dependabot"}}, &github.Repository{Archived: github.Bool(true)})
		if len(got) != 0 {
			t.Fatalf("files = %#v, want none", got)
		}
	})

	t.Run("explicit files still apply to forks", func(t *testing.T) {
		got := filesForRepo(selection, &github.Repository{Fork: github.Bool(true)})
		if !slices.Equal(got, wantExplicit) {
			t.Fatalf("files = %#v, want %#v", got, wantExplicit)
		}
	})

	t.Run("forks without explicit files get nothing", func(t *testing.T) {
		got := filesForRepo(config.ManagedFileSelection{Defaults: []string{"dependabot"}}, &github.Repository{Fork: github.Bool(true)})
		if len(got) != 0 {
			t.Fatalf("files = %#v, want none", got)
		}
	})

	t.Run("defaults apply regardless of repo size", func(t *testing.T) {
		got := filesForRepo(selection, &github.Repository{Size: github.Int(0)})
		if !slices.Equal(got, wantBoth) {
			t.Fatalf("files = %#v, want %#v", got, wantBoth)
		}
	})

	t.Run("missing metadata keeps explicit files only", func(t *testing.T) {
		got := filesForRepo(selection, nil)
		if !slices.Equal(got, wantExplicit) {
			t.Fatalf("files = %#v, want %#v", got, wantExplicit)
		}
	})
}
