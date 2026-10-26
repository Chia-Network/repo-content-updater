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
		"  - package-ecosystem: github-actions\n    directory: /extra\n    labels: [extra]\n"+
			"  - package-ecosystem: github-actions\n    directory: /extra\n    labels: [extra]\n")
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
	var extra int
	for _, u := range actions {
		if u["directory"] == "/extra" {
			extra++
			if labels, ok := u["labels"].([]any); !ok || !slices.Equal(labels, []any{"extra"}) {
				t.Fatalf("merged /extra block lost its labels: %v", u)
			}
		}
	}
	if extra != 1 {
		t.Fatalf("merged /extra blocks = %d, want one", extra)
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

// postRenderDefault finishes rendered as the default Dependabot file of a
// repo whose existing copy holds existing.
func postRenderDefault(t *testing.T, existing, rendered string) ([]byte, error) {
	t.Helper()
	return postRenderDefaultFiles(t, map[string]string{".github/dependabot.yml": existing}, rendered)
}

// postRenderDefaultFiles is postRenderDefault for a repo whose existing
// Dependabot files map each repo path to its contents.
func postRenderDefaultFiles(t *testing.T, existing map[string]string, rendered string) ([]byte, error) {
	t.Helper()
	fileinfo := loadDependabotTestConfig(t).GetFileInfo("dependabot-actions")
	dir := t.TempDir()
	for repoPath, body := range existing {
		writeDependabotTestFile(t, dir, repoPath, body)
	}
	selected := config.SelectedFile{Name: fileinfo.Name, Origin: config.OriginDefault}
	return postRenderForFile(dir, selected, fileinfo, []byte(rendered))
}

const renderedPipRoot = "version: 2\nupdates:\n  - package-ecosystem: pip\n    directory: /\n"

// TestPostRenderForFileConflictIsASkip reports a conflict between existing
// entries as a skip that names the conflict.
func TestPostRenderForFileConflictIsASkip(t *testing.T) {
	_, err := postRenderDefault(t, ""+
		"version: 2\nupdates:\n"+
		"  - package-ecosystem: pip\n    directory: /services\n    ignore:\n      - dependency-name: first\n"+
		"  - package-ecosystem: pip\n    directory: /services\n    ignore:\n      - dependency-name: second\n",
		renderedPipRoot)
	if !errors.Is(err, errConflictingDependabotEntries) || !errors.Is(err, errSkipManagedFile) {
		t.Fatalf("err = %v, want a skip for conflicting entries", err)
	}
}

// TestPostRenderForFileUnreadableIsASkipNotAConflict skips a default whose
// rendered or existing file is not YAML, and leaves an explicit file as rendered.
func TestPostRenderForFileUnreadableIsASkipNotAConflict(t *testing.T) {
	for name, files := range map[string][2]string{
		"rendered": {renderedPipRoot, "not: [valid yaml"},
		"existing": {"not: [valid yaml", renderedPipRoot},
	} {
		_, err := postRenderDefault(t, files[0], files[1])
		if !errors.Is(err, errSkipManagedFile) || errors.Is(err, errConflictingDependabotEntries) {
			t.Fatalf("%s: err = %v, want a skip that is not a conflict", name, err)
		}
	}
	fileinfo := loadDependabotTestConfig(t).GetFileInfo("dependabot")
	out, err := postRenderForFile(t.TempDir(), config.SelectedFile{Name: fileinfo.Name}, fileinfo, []byte("not: [valid yaml"))
	if err != nil || string(out) != "not: [valid yaml" {
		t.Fatalf("explicit = %q, %v; want the rendered bytes", out, err)
	}
}

// TestPostRenderForFileOverlappingDirectoriesConflict compares existing
// entries per directory: [/a, /b] and [/b] with different settings conflict,
// and with identical settings /b is kept once.
func TestPostRenderForFileOverlappingDirectoriesConflict(t *testing.T) {
	existing := func(second string) string {
		return "version: 2\nupdates:\n" +
			"  - package-ecosystem: pip\n    directories: [/a, /b]\n    ignore:\n      - dependency-name: first\n" +
			"  - package-ecosystem: pip\n    directories: [/b]\n    ignore:\n      - dependency-name: " + second + "\n"
	}
	if _, err := postRenderDefault(t, existing("second"), renderedPipRoot); !errors.Is(err, errConflictingDependabotEntries) {
		t.Fatalf("err = %v, want errConflictingDependabotEntries", err)
	}
	out, err := postRenderDefault(t, existing("first"), renderedPipRoot)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Updates []map[string]any `yaml:"updates"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if pip := entriesFor(doc.Updates, "pip"); len(pip) != 2 || fmt.Sprint(pip[1]["directories"]) != "[/a /b]" {
		t.Fatalf("pip entries = %v, want the rendered root plus one [/a /b] entry\n%s", pip, out)
	}
}

// TestPostRenderForFileCarriesReferencedRegistries copies the registry a kept
// entry references from the existing file, and aborts when the rendered file
// defines that registry name differently.
func TestPostRenderForFileCarriesReferencedRegistries(t *testing.T) {
	rendered := "version: 2\n" +
		"registries:\n  chia-pypi:\n    type: python-index\n    url: https://pypi.chia.net/simple/\n" +
		"updates:\n  - package-ecosystem: github-actions\n    directories:\n      - /\n"
	existing := func(name, url string) string {
		return "version: 2\n" +
			"registries:\n  " + name + ":\n    type: python-index\n    url: " + url + "\n" +
			"updates:\n  - package-ecosystem: pip\n    directory: /services\n    registries:\n      - " + name + "\n"
	}
	out, err := postRenderDefault(t, existing("private", "https://private.example/simple/"), rendered)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Registries map[string]map[string]string `yaml:"registries"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Registries["private"]["url"] != "https://private.example/simple/" {
		t.Fatalf("private registry not carried over:\n%s", out)
	}
	if _, kept := doc.Registries["chia-pypi"]; kept {
		t.Fatalf("unreferenced chia-pypi not pruned:\n%s", out)
	}
	_, err = postRenderDefault(t, existing("chia-pypi", "https://elsewhere.example/simple/"), rendered)
	if !errors.Is(err, errConflictingDependabotEntries) {
		t.Fatalf("err = %v, want errConflictingDependabotEntries for a redefined registry", err)
	}
}

// TestDefaultDependabotChiaGamingFixture renders the default for a repo with
// npm, cargo and github-actions but no Python, exercising the marker rename,
// registries pruning, and list-form directories.
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

	rendered, err := content.renderManagedFile(repoName, config.SelectedFile{Name: fileinfo.Name, Origin: config.OriginDefault}, fileinfo, cfg, Config{})
	if err != nil {
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
	for _, update := range doc.Updates {
		if update.Directory != "" || len(update.Directories) == 0 {
			t.Fatalf("%s block does not use a directories list: %#v", update.Ecosystem, update)
		}
		if update.Ecosystem == "github-actions" && update.Schedule["interval"] != "weekly" {
			t.Fatalf("github-actions interval = %v, want weekly", update.Schedule["interval"])
		}
	}
}

// TestPostRenderForFilePrunesAfterMerge keeps a registry that only a merged
// existing entry references; pruning before the merge would strand it.
func TestPostRenderForFilePrunesAfterMerge(t *testing.T) {
	out, err := postRenderDefault(t, ""+
		"version: 2\nupdates:\n"+
		"  - package-ecosystem: pip\n    directories:\n      - /services\n    registries:\n      - chia-pypi\n",
		"version: 2\n"+
			"registries:\n  chia-pypi:\n    type: python-index\n    url: https://pypi.chia.net/simple/\n"+
			"  unused:\n    type: python-index\n    url: https://example.invalid/simple/\n"+
			"updates:\n  - package-ecosystem: github-actions\n    directories:\n      - /\n")
	if err != nil {
		t.Fatal(err)
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

type dependabotTestDoc struct {
	Registries map[string]map[string]string `yaml:"registries"`
	Updates    []map[string]any             `yaml:"updates"`
}

func parseDependabotTestDoc(t *testing.T, out []byte) dependabotTestDoc {
	t.Helper()
	var doc dependabotTestDoc
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	return doc
}

// TestPostRenderForFileIdenticalActionsEntriesDoNotConflict compares every
// existing github-actions entry before any is moved to a weekly interval, so
// identical settings that share a directory, or the same entry in both
// dependabot.yml and dependabot.yaml, are kept once instead of conflicting.
// Mapping keys compare by key, not by order.
func TestPostRenderForFileIdenticalActionsEntriesDoNotConflict(t *testing.T) {
	entry := func(dirs, schedule string) string {
		return "  - package-ecosystem: github-actions\n    directories: " + dirs + "\n    schedule: " + schedule + "\n"
	}
	for name, existing := range map[string]map[string]string{
		"overlapping directories": {".github/dependabot.yml": "version: 2\nupdates:\n" +
			entry("[/a, /b]", "{interval: daily, time: \"09:00\"}") +
			entry("[/b]", "{time: \"09:00\", interval: daily}")},
		"both file names": {
			".github/dependabot.yml":  "version: 2\nupdates:\n" + entry("[/a, /b]", "{interval: daily}"),
			".github/dependabot.yaml": "version: 2\nupdates:\n" + entry("[/a, /b]", "{interval: daily}"),
		},
	} {
		out, err := postRenderDefaultFiles(t, existing, renderedPipRoot)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		actions := entriesFor(parseDependabotTestDoc(t, out).Updates, "github-actions")
		if len(actions) != 1 || fmt.Sprint(actions[0]["directories"]) != "[/a /b]" {
			t.Fatalf("%s: github-actions entries = %v, want one [/a /b] entry\n%s", name, actions, out)
		}
		if schedule, _ := actions[0]["schedule"].(map[string]any); schedule["interval"] != "weekly" {
			t.Fatalf("%s: github-actions schedule = %v, want weekly", name, actions[0]["schedule"])
		}
	}
}

// TestPostRenderForFileConflictAcrossFileNames compares entries of
// dependabot.yml and dependabot.yaml with each other, and the conflict names
// the branch it is on.
func TestPostRenderForFileConflictAcrossFileNames(t *testing.T) {
	entry := func(ignored string) string {
		return "version: 2\nupdates:\n  - package-ecosystem: pip\n    directory: /services\n    ignore:\n      - dependency-name: " + ignored + "\n"
	}
	_, err := postRenderDefaultFiles(t, map[string]string{
		".github/dependabot.yml":  entry("first"),
		".github/dependabot.yaml": entry("second"),
	}, renderedPipRoot)
	if !errors.Is(err, errConflictingDependabotEntries) || !strings.Contains(err.Error(), "/services differently on the default branch") {
		t.Fatalf("err = %v, want a conflict for /services on the default branch", err)
	}
}

// TestPostRenderForFileCarriesWildcardRegistries copies every registry of the
// existing file for a kept entry that uses registries: "*".
func TestPostRenderForFileCarriesWildcardRegistries(t *testing.T) {
	out, err := postRenderDefault(t, "version: 2\n"+
		"registries:\n"+
		"  first:\n    type: python-index\n    url: https://first.example/simple/\n"+
		"  second:\n    type: python-index\n    url: https://second.example/simple/\n"+
		"updates:\n  - package-ecosystem: pip\n    directory: /services\n    registries: \"*\"\n",
		"version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directories:\n      - /\n")
	if err != nil {
		t.Fatal(err)
	}
	doc := parseDependabotTestDoc(t, out)
	if doc.Registries["first"]["url"] != "https://first.example/simple/" || doc.Registries["second"]["url"] != "https://second.example/simple/" {
		t.Fatalf("registries = %v, want first and second carried over\n%s", doc.Registries, out)
	}
}
