package repo

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/chia-network/repo-content-updater/internal/config"
)

// mergeDefaultDependabot adopts a repo whose existing dependabot.yml lists
// updates and returns the parsed updates of the file written.
func mergeDefaultDependabot(t *testing.T, repoName, updates string) []map[string]any {
	t.Helper()
	cfg := loadDependabotTestConfig(t)
	templates, err := filepath.Abs(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	content := &Content{templates: templates}
	marker := "# " + cfg.GetFileInfo("dependabot-actions").AdoptionMarker
	selection := config.ManagedFileSelection{Defaults: []config.DefaultBundle{{Root: "dependabot-actions", Files: []string{"dependabot-actions"}}}}
	original := "# managed by the repo-content-updater\n" + marker + "\nversion: 2\nupdates:\n" + updates
	writeDependabotTestFile(t, repoDir(repoName), ".github/dependabot.yml", original)
	writeDependabotTestFile(t, repoDir(repoName), ".github/workflows/ci.yml", "")
	if err := content.applySelection(repoName, selection, cfg, Config{}, func(string, []string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(repoDir(repoName), ".github", "dependabot.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), marker) {
		t.Fatalf("adoption marker lost:\n%s", body)
	}
	var doc struct {
		Updates []map[string]any `yaml:"updates"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("%v:\n%s", err, body)
	}
	return doc.Updates
}

func entriesFor(updates []map[string]any, eco string) []map[string]any {
	var out []map[string]any
	for _, u := range updates {
		if u["package-ecosystem"] == eco {
			out = append(out, u)
		}
	}
	return out
}

func TestDefaultDependabotNeverDropsExistingEcosystems(t *testing.T) {
	for name, eco := range map[string]string{
		"a template ecosystem without a detected manifest": "npm",
		"an ecosystem the template does not render":        "bundler",
	} {
		t.Run(name, func(t *testing.T) {
			updates := mergeDefaultDependabot(t, strings.ReplaceAll(name, " ", "-"),
				"  - package-ecosystem: github-actions\n    directory: /\n  - package-ecosystem: "+eco+"\n    directory: /\n")
			if got := entriesFor(updates, eco); len(got) != 1 || got[0]["directory"] != "/" {
				t.Fatalf("%s entry not kept: %v", eco, updates)
			}
		})
	}
}

func TestDefaultDependabotKeepsUncoveredDirectories(t *testing.T) {
	updates := mergeDefaultDependabot(t, "dirs",
		"  - package-ecosystem: github-actions\n    directories: [\"/\", \"/tools\"]\n")
	var dirs []any
	for _, u := range entriesFor(updates, "github-actions") {
		if d, ok := u["directory"]; ok {
			dirs = append(dirs, d)
		}
		if d, ok := u["directories"].([]any); ok {
			dirs = append(dirs, d...)
		}
	}
	if !slices.Contains(dirs, any("/tools")) {
		t.Fatalf("/tools dropped: %v", updates)
	}
}

func TestDefaultDependabotWritesOneActionsBlockPerKey(t *testing.T) {
	updates := mergeDefaultDependabot(t, "actions",
		"  - package-ecosystem: github-actions\n    directory: /extra\n    schedule:\n      interval: daily\n"+
			"  - package-ecosystem: github-actions\n    directory: /extra/\n")
	actions := entriesFor(updates, "github-actions")
	if len(actions) != 2 {
		t.Fatalf("want the rendered block plus one /extra block, got %v", actions)
	}
	for _, u := range actions {
		schedule, _ := u["schedule"].(map[string]any)
		reviewers, _ := u["reviewers"].([]any)
		if schedule["interval"] != "weekly" || !slices.Equal(reviewers, []any{"cameroncooper", "emlowe"}) {
			t.Fatalf("github-actions block not weekly with reviewers: %v", u)
		}
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
