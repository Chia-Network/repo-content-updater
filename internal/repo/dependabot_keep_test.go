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
		"  - package-ecosystem: github-actions\n    directory: /extra\n    reviewers: [alice]\n"+
			"  - package-ecosystem: github-actions\n    directory: /extra\n    reviewers: [alice]\n")
	actions := entriesFor(updates, "github-actions")
	if len(actions) != 2 {
		t.Fatalf("want the rendered block plus one /extra block, got %v", actions)
	}
	for _, u := range actions {
		schedule, _ := u["schedule"].(map[string]any)
		if schedule["interval"] != "weekly" {
			t.Fatalf("github-actions block not weekly: %v", u)
		}
	}
	var extra []any
	for _, u := range actions {
		if u["directory"] == "/extra" {
			extra, _ = u["reviewers"].([]any)
		}
	}
	if !slices.Equal(extra, []any{"alice"}) {
		t.Fatalf("merged /extra reviewers = %v, want [alice]", extra)
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

func TestDefaultDependabotConflictingDuplicateEntriesLeaveTheFileUnchanged(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	templates, err := filepath.Abs(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	content := &Content{templates: templates}
	repoName := "conflict"
	marker := "# " + cfg.GetFileInfo("dependabot-actions").AdoptionMarker
	selection := config.ManagedFileSelection{Defaults: []config.DefaultBundle{{Root: "dependabot-actions", Files: []string{"dependabot-actions"}}}}
	updates := "" +
		"  - package-ecosystem: pip\n" +
		"    directory: /services\n" +
		"    ignore:\n" +
		"      - dependency-name: first\n" +
		"  - package-ecosystem: pip\n" +
		"    directory: /services\n" +
		"    ignore:\n" +
		"      - dependency-name: second\n"
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
	if string(body) != original {
		t.Fatalf("conflicting duplicate entries were rewritten:\n--- got ---\n%s\n--- want ---\n%s", body, original)
	}
}

// TestDefaultDependabotChiaGamingFixture renders the default for a repo with
// npm, cargo and github-actions but no Python, exercising the marker rename,
// per-block reviewers, registries pruning, and list-form directories.
func TestDefaultDependabotChiaGamingFixture(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	templates, err := filepath.Abs(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	content := &Content{templates: templates}
	fileinfo := cfg.GetFileInfo("dependabot-actions")
	repoName := "chia-gaming"
	writeDependabotTestFile(t, repoDir(repoName), "package.json", "{}")
	writeDependabotTestFile(t, repoDir(repoName), "Cargo.toml", "")
	writeDependabotTestFile(t, repoDir(repoName), filepath.Join(".github", "workflows", "ci.yml"), "")

	rendered, ok, err := content.renderManagedFile(repoName, config.SelectedFile{Name: fileinfo.Name, Origin: config.OriginDefault}, fileinfo, cfg, Config{})
	if err != nil || !ok {
		t.Fatal(err)
	}
	if !containsTrimmedLine(string(rendered), "# "+fileinfo.AdoptionMarker) {
		t.Fatalf("rendered default lost its adoption marker\n%s", rendered)
	}
	var doc struct {
		Registries map[string]any `yaml:"registries"`
		Updates    []struct {
			Ecosystem   string         `yaml:"package-ecosystem"`
			Directory   string         `yaml:"directory"`
			Directories []string       `yaml:"directories"`
			Schedule    map[string]any `yaml:"schedule"`
			Reviewers   []string       `yaml:"reviewers"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal(rendered, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Registries) != 0 {
		t.Fatalf("registries = %#v, want none without pip", doc.Registries)
	}
	if got := renderedDependabotEcosystems(t, rendered); got != "github-actions,npm,cargo" {
		t.Fatalf("ecosystems = %q, want github-actions,npm,cargo\n%s", got, rendered)
	}
	wantReviewers := map[string][]string{
		"npm":            {"emlowe", "seeden"},
		"cargo":          {"cameroncooper", "emlowe"},
		"github-actions": {"cameroncooper", "emlowe"},
	}
	for _, update := range doc.Updates {
		if update.Directory != "" || len(update.Directories) == 0 {
			t.Fatalf("%s block does not use a directories list: %#v", update.Ecosystem, update)
		}
		if !slices.Equal(update.Reviewers, wantReviewers[update.Ecosystem]) {
			t.Fatalf("%s reviewers = %v, want %v", update.Ecosystem, update.Reviewers, wantReviewers[update.Ecosystem])
		}
		if update.Ecosystem == "github-actions" && update.Schedule["interval"] != "weekly" {
			t.Fatalf("github-actions interval = %v, want weekly", update.Schedule["interval"])
		}
	}
}
