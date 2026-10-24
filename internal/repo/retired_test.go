package repo

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/chia-network/repo-content-updater/internal/config"
)

// retiredTestContent is a Content and Config with one file, "tool", that
// renames .github/tool.yaml and retires two paths, from a scratch working
// directory.
func retiredTestContent(t *testing.T) (*Content, *config.Config) {
	t.Helper()
	root := t.TempDir()
	templates := filepath.Join(root, "templates")
	if err := os.MkdirAll(templates, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(templates, "tool.yml"), []byte("tool: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(configPath, []byte(`
files:
  - name: tool
    template_name: tool.yml
    repo_path: .github/tool.yml
    alternate_paths:
      - .github/tool.yaml
    retired_paths:
      - .github/actions/old/action.yml
      - .github/scripts/old_helper.py
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	return &Content{templates: templates}, cfg
}

func TestApplySelectionDeletesRetiredPaths(t *testing.T) {
	content, cfg := retiredTestContent(t)
	repoName := "retired"
	outside := filepath.Join(t.TempDir(), "kept.py")
	if err := os.WriteFile(outside, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeDependabotTestFile(t, repoDir(repoName), ".github/actions/old/action.yml", "old\n")
	writeDependabotTestFile(t, repoDir(repoName), ".github/scripts/current.py", "current\n")
	if err := os.Symlink(outside, filepath.Join(repoDir(repoName), ".github", "scripts", "old_helper.py")); err != nil {
		t.Fatal(err)
	}

	var staged [][]string
	err := content.applySelection(repoName, config.ManagedFileSelection{Explicit: []string{"tool"}}, cfg, Config{}, func(_ string, repoPaths []string) error {
		staged = append(staged, repoPaths)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, retired := range []string{".github/actions/old/action.yml", ".github/scripts/old_helper.py"} {
		if _, err := os.Lstat(filepath.Join(repoDir(repoName), retired)); !os.IsNotExist(err) {
			t.Errorf("%s still exists: %v", retired, err)
		}
	}
	if body, err := os.ReadFile(outside); err != nil || string(body) != "keep\n" {
		t.Errorf("link target = %q, %v; want it unchanged", body, err)
	}
	if body, err := os.ReadFile(filepath.Join(repoDir(repoName), ".github", "scripts", "current.py")); err != nil || string(body) != "current\n" {
		t.Errorf("unretired sibling = %q, %v; want it unchanged", body, err)
	}
	want := [][]string{{".github/tool.yml", ".github/tool.yaml", ".github/actions/old/action.yml", ".github/scripts/old_helper.py"}}
	if !reflect.DeepEqual(staged, want) {
		t.Errorf("staged %v, want %v", staged, want)
	}
}

func TestApplySelectionKeepsRetiredPathsBehindALinkedParent(t *testing.T) {
	content, cfg := retiredTestContent(t)
	repoName := "linked-actions"
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "old", "action.yml")
	writeDependabotTestFile(t, outside, "old/action.yml", "keep\n")
	if err := os.MkdirAll(filepath.Join(repoDir(repoName), ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(repoDir(repoName), ".github", "actions")); err != nil {
		t.Fatal(err)
	}

	err := content.applySelection(repoName, config.ManagedFileSelection{Explicit: []string{"tool"}}, cfg, Config{}, func(string, []string) error { return nil })
	if err == nil {
		t.Fatal("expected an error for a linked .github/actions directory")
	}
	if body, err := os.ReadFile(outsideFile); err != nil || string(body) != "keep\n" {
		t.Fatalf("outside file = %q, %v; want it unchanged", body, err)
	}
	if _, err := os.Lstat(filepath.Join(repoDir(repoName), ".github", "tool.yml")); !os.IsNotExist(err) {
		t.Fatalf("tool.yml was written before the failing path was checked: %v", err)
	}
}
