package repo

import (
	"errors"
	"fmt"
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

// dependabotEcosystemNames returns the rendered update ecosystems in order.
func dependabotEcosystemNames(raw []byte) ([]string, bool) {
	var doc yaml.Node
	updates, ok := dependabotUpdates(raw, &doc)
	if !ok {
		return nil, false
	}
	names := make([]string, 0, len(updates.Content))
	for _, entry := range updates.Content {
		eco, _, _ := entryKey(entry)
		names = append(names, eco)
	}
	return names, true
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

// TestDefaultDependabotKeepsTargetBranchEntries leaves every target-branch
// entry untouched: a target-branch entry is never covered by the rendered
// default, and two entries that differ only by target-branch do not conflict.
func TestDefaultDependabotKeepsTargetBranchEntries(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	templates, err := filepath.Abs(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	content := &Content{templates: templates}
	repoName := "target-branch"
	marker := "# " + cfg.GetFileInfo("dependabot-actions").AdoptionMarker
	selection := config.ManagedFileSelection{Defaults: []config.DefaultBundle{{Root: "dependabot-actions", Files: []string{"dependabot-actions"}}}}
	updates := "" +
		"  - package-ecosystem: pip\n" +
		"    directory: /\n" +
		"    target-branch: release\n" +
		"  - package-ecosystem: pip\n" +
		"    directory: /\n" +
		"    target-branch: main\n"
	original := "# managed by the repo-content-updater\n" + marker + "\nversion: 2\nupdates:\n" + updates
	writeDependabotTestFile(t, repoDir(repoName), ".github/dependabot.yml", original)
	writeDependabotTestFile(t, repoDir(repoName), ".github/workflows/ci.yml", "")
	writeDependabotTestFile(t, repoDir(repoName), "requirements.txt", "")
	if err := content.applySelection(repoName, selection, cfg, Config{}, func(string, []string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(repoDir(repoName), ".github", "dependabot.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Updates []map[string]any `yaml:"updates"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	pip := entriesFor(doc.Updates, "pip")
	if len(pip) != 3 {
		t.Fatalf("pip entries = %v, want rendered + release + main", doc.Updates)
	}
	var branches []string
	for _, update := range pip {
		branches = append(branches, fmt.Sprint(update["target-branch"]))
	}
	slices.Sort(branches)
	if !slices.Equal(branches, []string{"<nil>", "main", "release"}) {
		t.Fatalf("target-branches = %v, want [<nil> main release]\n%s", branches, body)
	}
}

// TestDefaultDependabotMissingDirectoryDefaultsToRoot keys a directory-less
// entry as "/", so it collapses into the rendered root entry instead of being
// written as a duplicate.
func TestDefaultDependabotMissingDirectoryDefaultsToRoot(t *testing.T) {
	updates := mergeDefaultDependabot(t, "missing-dir",
		"  - package-ecosystem: github-actions\n    directory: /\n  - package-ecosystem: pip\n")
	pip := entriesFor(updates, "pip")
	if len(pip) != 1 {
		t.Fatalf("pip entries = %v, want a single root entry", updates)
	}
}

// TestDefaultDependabotTargetBranchDoesNotCoverPlainEntries keeps a plain
// entry at a directory a target-branch entry also uses: the two update
// different branches and are not the same coverage.
func TestDefaultDependabotTargetBranchDoesNotCoverPlainEntries(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	templates, err := filepath.Abs(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	content := &Content{templates: templates}
	repoName := "target-branch-overlap"
	marker := "# " + cfg.GetFileInfo("dependabot-actions").AdoptionMarker
	selection := config.ManagedFileSelection{Defaults: []config.DefaultBundle{{Root: "dependabot-actions", Files: []string{"dependabot-actions"}}}}
	updates := "" +
		"  - package-ecosystem: pip\n    directory: /services\n    target-branch: release\n" +
		"  - package-ecosystem: pip\n    directory: /services\n"
	original := "# managed by the repo-content-updater\n" + marker + "\nversion: 2\nupdates:\n" + updates
	writeDependabotTestFile(t, repoDir(repoName), ".github/dependabot.yml", original)
	writeDependabotTestFile(t, repoDir(repoName), ".github/workflows/ci.yml", "")
	writeDependabotTestFile(t, repoDir(repoName), "requirements.txt", "")
	if err := content.applySelection(repoName, selection, cfg, Config{}, func(string, []string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(repoDir(repoName), ".github", "dependabot.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Updates []map[string]any `yaml:"updates"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	pip := entriesFor(doc.Updates, "pip")
	if len(pip) != 3 {
		t.Fatalf("pip entries = %v, want rendered + target-branch + plain", doc.Updates)
	}
	var plain int
	var release int
	for _, update := range pip {
		switch fmt.Sprint(update["target-branch"]) {
		case "release":
			release++
		case "<nil>":
			if update["directory"] == "/services" {
				plain++
			}
		}
	}
	if plain != 1 || release != 1 {
		t.Fatalf("pip entries = %v, want one plain /services and one release /services\n%s", pip, body)
	}
}

// TestMergeDependabotConfigConflictIsATypedError distinguishes a conflict
// between existing entries from an unreadable file.
func TestMergeDependabotConfigConflictIsATypedError(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	fileinfo := cfg.GetFileInfo("dependabot-actions")
	dir := t.TempDir()
	writeDependabotTestFile(t, dir, fileinfo.RepoPath, ""+
		"version: 2\nupdates:\n"+
		"  - package-ecosystem: pip\n    directory: /services\n    ignore:\n      - dependency-name: first\n"+
		"  - package-ecosystem: pip\n    directory: /services\n    ignore:\n      - dependency-name: second\n")
	rendered := []byte("version: 2\nupdates:\n  - package-ecosystem: pip\n    directory: /\n")
	_, _, err := mergeDependabotConfig(dir, fileinfo, rendered)
	if !errors.Is(err, errConflictingDependabotEntries) {
		t.Fatalf("err = %v, want errConflictingDependabotEntries", err)
	}
}

// TestMergeDependabotConfigUnreadableRenderedIsNotConflicting reports an
// unreadable rendered file as ok=false with no error, not as a conflict.
func TestMergeDependabotConfigUnreadableRenderedIsNotConflicting(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	fileinfo := cfg.GetFileInfo("dependabot-actions")
	_, ok, err := mergeDependabotConfig(t.TempDir(), fileinfo, []byte("not: [valid yaml"))
	if err != nil || ok {
		t.Fatalf("ok = %v, err = %v; want ok=false and no error", ok, err)
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

// TestPostRenderDependabotPrunesAfterMerge keeps a registry that only a merged
// existing block references; pruning before the merge would strand it.
func TestPostRenderDependabotPrunesAfterMerge(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	fileinfo := cfg.GetFileInfo("dependabot-actions")
	dir := t.TempDir()
	writeDependabotTestFile(t, dir, fileinfo.RepoPath, ""+
		"version: 2\nupdates:\n"+
		"  - package-ecosystem: pip\n    directories:\n      - /services\n    registries:\n      - chia-pypi\n")
	rendered := []byte("version: 2\n" +
		"registries:\n  chia-pypi:\n    type: python-index\n    url: https://pypi.chia.net/simple/\n" +
		"  unused:\n    type: python-index\n    url: https://example.invalid/simple/\n" +
		"updates:\n  - package-ecosystem: github-actions\n    directories:\n      - /\n")
	selected := config.SelectedFile{Name: "dependabot-actions", Origin: config.OriginDefault}
	out, ok, err := postRenderDependabot(dir, selected, fileinfo, rendered)
	if err != nil || !ok {
		t.Fatalf("ok = %v, err = %v", ok, err)
	}
	var doc struct {
		Registries map[string]any `yaml:"registries"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if _, kept := doc.Registries["chia-pypi"]; !kept {
		t.Fatalf("chia-pypi pruned though a merged block uses it:\n%s", out)
	}
	if _, kept := doc.Registries["unused"]; kept {
		t.Fatalf("unused registry not pruned:\n%s", out)
	}
}
