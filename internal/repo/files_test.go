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
	templates, err := filepath.Abs(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	content := &Content{templates: templates}
	fileinfo := &config.File{
		Name:           "dependabot-actions",
		TemplateName:   "dependabot-actions.yml",
		RepoPath:       ".github/dependabot.yml",
		AlternatePaths: []string{".github/dependabot.yaml"},
		AdoptionMarker: "repo-content-updater:dependabot-actions",
	}
	markerLine := "# " + fileinfo.AdoptionMarker
	fullManagedFirstLine := "# This file is managed by the repo-content-updater project. Manual changes here will result in a PR to bring back"

	t.Run("creates when absent", func(t *testing.T) {
		adopt, err := content.shouldAdoptExistingFile("absent", fileinfo)
		if err != nil {
			t.Fatal(err)
		}
		if !adopt {
			t.Fatal("absent file should be adopted")
		}
	})

	t.Run("skips an unmarked existing file", func(t *testing.T) {
		writeDependabotTestFile(t, repoDir("unmarked"), fileinfo.RepoPath, "version: 2\n")
		adopt, err := content.shouldAdoptExistingFile("unmarked", fileinfo)
		if err != nil {
			t.Fatal(err)
		}
		if adopt {
			t.Fatal("unmarked file should not be adopted")
		}
	})

	t.Run("skips a full managed config carrying the generic marker", func(t *testing.T) {
		writeDependabotTestFile(t, repoDir("full-managed"), fileinfo.RepoPath, fullManagedFirstLine+"\n# inline with the upstream template, unless you add !dependabot to the repo's managed-files property\nversion: 2\n")
		adopt, err := content.shouldAdoptExistingFile("full-managed", fileinfo)
		if err != nil {
			t.Fatal(err)
		}
		if adopt {
			t.Fatal("full managed config should not be adopted")
		}
	})

	t.Run("updates a file carrying the adoption marker", func(t *testing.T) {
		writeDependabotTestFile(t, repoDir("actions-default"), fileinfo.RepoPath, markerLine+"\nversion: 2\n")
		adopt, err := content.shouldAdoptExistingFile("actions-default", fileinfo)
		if err != nil {
			t.Fatal(err)
		}
		if !adopt {
			t.Fatal("marked file should be adopted")
		}
	})

	t.Run("updates a file carrying the adoption marker at the alternate path", func(t *testing.T) {
		writeDependabotTestFile(t, repoDir("actions-alternate"), fileinfo.AlternatePaths[0], markerLine+"\nversion: 2\n")
		adopt, err := content.shouldAdoptExistingFile("actions-alternate", fileinfo)
		if err != nil {
			t.Fatal(err)
		}
		if !adopt {
			t.Fatal("marked alternate should be adopted")
		}
	})

	t.Run("skips an unmarked alternate path", func(t *testing.T) {
		writeDependabotTestFile(t, repoDir("alternate"), fileinfo.AlternatePaths[0], "version: 2\n")
		adopt, err := content.shouldAdoptExistingFile("alternate", fileinfo)
		if err != nil {
			t.Fatal(err)
		}
		if adopt {
			t.Fatal("unmarked alternate should not be adopted")
		}
	})

	t.Run("writes an absent file without an adoption marker", func(t *testing.T) {
		unmarked := *fileinfo
		unmarked.AdoptionMarker = ""
		adopt, err := content.shouldAdoptExistingFile("unmarked-absent", &unmarked)
		if err != nil {
			t.Fatal(err)
		}
		if !adopt {
			t.Fatal("absent file without a marker should be adopted")
		}
	})

	t.Run("skips an existing file without an adoption marker", func(t *testing.T) {
		unmarked := *fileinfo
		unmarked.AdoptionMarker = ""
		writeDependabotTestFile(t, repoDir("unmarked-existing"), unmarked.RepoPath, markerLine+"\nversion: 2\n")
		adopt, err := content.shouldAdoptExistingFile("unmarked-existing", &unmarked)
		if err != nil {
			t.Fatal(err)
		}
		if adopt {
			t.Fatal("existing file without a marker should not be adopted")
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

func TestPrepareManagedFileDefaultActionsAdoption(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	templates, err := filepath.Abs(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	content := &Content{templates: templates}
	fileinfo := cfg.GetFileInfo("dependabot-actions")
	if fileinfo == nil {
		t.Fatal("dependabot-actions file missing from config")
	}
	markerLine := "# " + fileinfo.AdoptionMarker
	fullManagedFirstLine := "# This file is managed by the repo-content-updater project. Manual changes here will result in a PR to bring back"

	t.Run("writes when absent", func(t *testing.T) {
		rendered, skip, err := content.prepareManagedFile("actions-absent", fileinfo, config.OriginDefault, cfg, Config{})
		if err != nil {
			t.Fatal(err)
		}
		if skip {
			t.Fatal("absent default should be written")
		}
		if len(rendered) == 0 {
			t.Fatal("rendered content is empty")
		}
	})

	t.Run("writes a file carrying the adoption marker", func(t *testing.T) {
		writeDependabotTestFile(t, repoDir("actions-marked"), fileinfo.RepoPath, markerLine+"\nversion: 2\n")
		_, skip, err := content.prepareManagedFile("actions-marked", fileinfo, config.OriginDefault, cfg, Config{})
		if err != nil {
			t.Fatal(err)
		}
		if skip {
			t.Fatal("marked file should be written")
		}
	})

	t.Run("writes a file carrying the adoption marker at the alternate path", func(t *testing.T) {
		writeDependabotTestFile(t, repoDir("actions-alternate"), fileinfo.AlternatePaths[0], markerLine+"\nversion: 2\n")
		_, skip, err := content.prepareManagedFile("actions-alternate", fileinfo, config.OriginDefault, cfg, Config{})
		if err != nil {
			t.Fatal(err)
		}
		if skip {
			t.Fatal("marked alternate should be written")
		}
	})

	t.Run("skips a full managed config carrying the generic marker", func(t *testing.T) {
		writeDependabotTestFile(t, repoDir("actions-full"), fileinfo.RepoPath, fullManagedFirstLine+"\nversion: 2\n")
		_, skip, err := content.prepareManagedFile("actions-full", fileinfo, config.OriginDefault, cfg, Config{})
		if err != nil {
			t.Fatal(err)
		}
		if !skip {
			t.Fatal("full managed config should not be overwritten")
		}
	})

	t.Run("skips an unmarked file", func(t *testing.T) {
		writeDependabotTestFile(t, repoDir("actions-unmarked"), fileinfo.RepoPath, "version: 2\n")
		_, skip, err := content.prepareManagedFile("actions-unmarked", fileinfo, config.OriginDefault, cfg, Config{})
		if err != nil {
			t.Fatal(err)
		}
		if !skip {
			t.Fatal("unmarked file should not be adopted")
		}
	})
}

func TestFilesForRepo(t *testing.T) {
	selection := config.ManagedFileSelection{
		Explicit: []string{"dep-review"},
		Defaults: []string{"dependabot-actions"},
	}
	wantBoth := []config.SelectedFile{
		{Name: "dep-review", Origin: config.OriginExplicit},
		{Name: "dependabot-actions", Origin: config.OriginDefault},
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
		got := filesForRepo(config.ManagedFileSelection{Defaults: []string{"dependabot-actions"}}, &github.Repository{Archived: github.Bool(true)})
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
		got := filesForRepo(config.ManagedFileSelection{Defaults: []string{"dependabot-actions"}}, &github.Repository{Fork: github.Bool(true)})
		if len(got) != 0 {
			t.Fatalf("files = %#v, want none", got)
		}
	})

	t.Run("name rules decide default eligibility", func(t *testing.T) {
		tests := []struct {
			repoName string
			want     []config.SelectedFile
		}{
			{repoName: "chiavdf-private", want: wantExplicit},
			{repoName: "private-chiapos", want: wantExplicit},
			{repoName: "chiavdf-dos", want: wantExplicit},
			{repoName: "Chia-DOS", want: wantExplicit},
			{repoName: "dosbox", want: wantBoth},
		}
		for _, tt := range tests {
			t.Run(tt.repoName, func(t *testing.T) {
				got := filesForRepo(selection, &github.Repository{Name: github.String(tt.repoName)})
				if !slices.Equal(got, tt.want) {
					t.Fatalf("files = %#v, want %#v", got, tt.want)
				}
			})
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
