package repo

import (
	"maps"
	"path/filepath"
	"testing"

	"github.com/chia-network/repo-content-updater/internal/config"
)

func TestTemplateInputsForFile(t *testing.T) {
	t.Chdir(t.TempDir())
	repoName := "wiring"
	writeDependabotTestFile(t, repoDir(repoName), filepath.Join("pkg", "requirements.txt"), "")
	writeDependabotTestFile(t, repoDir(repoName), "package.json", "{}")

	cfg := &config.Config{Variables: map[string]string{
		"BASE_VAR":                 "base",
		"DEPENDABOT_PIP_DIRECTORY": "/",
	}}
	repoConfig := Config{VarOverrides: map[string]string{
		"DEPENDABOT_PIP_DIRECTORY": "pkg",
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
			"DEPENDABOT_PIP_DIRECTORY": "pkg",
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
