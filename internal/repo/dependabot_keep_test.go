package repo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chia-network/repo-content-updater/internal/config"
)

func TestDefaultDependabotNeverDropsExistingEcosystems(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	templates, err := filepath.Abs(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	content := &Content{templates: templates}
	marker := "# " + cfg.GetFileInfo("dependabot-actions").AdoptionMarker
	selection := config.ManagedFileSelection{Defaults: []config.DefaultBundle{{Root: "dependabot-actions", Files: []string{"dependabot-actions"}}}}

	for name, extra := range map[string]string{
		"a template ecosystem without a detected manifest": "  - package-ecosystem: npm\n    directory: /\n",
		"an ecosystem the template does not render":        "  - package-ecosystem: bundler\n    directory: /\n",
	} {
		t.Run(name, func(t *testing.T) {
			repoName := strings.ReplaceAll(name, " ", "-")
			original := "# managed by the repo-content-updater\n" + marker + "\nversion: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n" + extra
			writeDependabotTestFile(t, repoDir(repoName), ".github/dependabot.yml", original)
			writeDependabotTestFile(t, repoDir(repoName), ".github/workflows/ci.yml", "")
			var staged []string
			err := content.applySelection(repoName, selection, cfg, Config{}, func(file string, _ []string) error {
				staged = append(staged, file)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(filepath.Join(repoDir(repoName), ".github", "dependabot.yml"))
			if err != nil {
				t.Fatal(err)
			}
			if len(staged) != 0 || string(body) != original {
				t.Fatalf("staged %v; file changed to:\n%s", staged, body)
			}
		})
	}
}

func TestDependabotTemplateRendersEachEcosystemOnce(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	for mask := 1; mask < 1<<len(dependabotEcosystems); mask++ {
		vars := copyTemplateVars(cfg.Variables)
		for i, ecosystem := range dependabotEcosystems {
			vars[ecosystem.enabledVar] = "0"
			if mask&(1<<i) != 0 {
				vars[ecosystem.enabledVar] = "1"
			}
		}
		names, ok := dependabotEcosystemNames(renderDependabotTemplate(t, cfg, vars))
		if !ok {
			t.Fatalf("mask %b: rendered configuration is not YAML", mask)
		}
		seen := map[string]bool{}
		for _, name := range names {
			if seen[name] {
				t.Fatalf("mask %b: %s rendered twice in %v", mask, name, names)
			}
			seen[name] = true
		}
	}
}
