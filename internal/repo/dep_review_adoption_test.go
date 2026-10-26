package repo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chia-network/repo-content-updater/internal/config"
)

// TestDependencyReviewAdoptionMarkers covers which headers adopt a managed
// file. An earlier release header adopts dep-review; a header shared with
// other templates, and another file carrying only that dep-review marker, do
// not.
func TestDependencyReviewAdoptionMarkers(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	templates, err := filepath.Abs(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	content := &Content{templates: templates}
	retired := []string{
		".github/workflows/dependency-cursor-review.yml",
		".github/scripts/malware_verdict_formatter.py",
	}

	const (
		earlierHeader = "# Managed by repo-content-updater"
		sharedHeader  = "# This file is managed by the repo-content-updater project. Manual changes here will result in a PR to bring back"
	)

	tests := []struct {
		name         string
		file         string
		content      string
		adopted      bool
		checkRetired bool
	}{
		{name: "earlier release header", file: "dep-review", content: earlierHeader + "\nname: old\n", adopted: true, checkRetired: true},
		{name: "shared template header", file: "dep-review", content: sharedHeader + "\nname: old\n", adopted: false, checkRetired: true},
		{name: "hand-written file", file: "dep-review", content: "name: old\n", adopted: false, checkRetired: true},
		{name: "earlier header mid-line", file: "dep-review", content: "foo # Managed by repo-content-updater\nname: old\n", adopted: false, checkRetired: true},
		{name: "earlier header does not adopt another file", file: "dependabot-actions", content: earlierHeader + "\nversion: 2\n", adopted: false},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileinfo := cfg.GetFileInfo(tt.file)
			if fileinfo == nil {
				t.Fatalf("managed file %q not found", tt.file)
			}
			selection := config.ManagedFileSelection{Defaults: []config.DefaultBundle{{
				Root:  tt.file,
				Files: []string{tt.file},
			}}}

			repoName := fmt.Sprintf("dep-review-%d", i)
			dir := repoDir(repoName)
			writeDependabotTestFile(t, dir, ".github/workflows/placeholder.yml", "name: placeholder\n")
			writeDependabotTestFile(t, dir, fileinfo.RepoPath, tt.content)
			if tt.checkRetired {
				for _, rel := range retired {
					writeDependabotTestFile(t, dir, rel, "legacy\n")
				}
			}

			if err := content.applySelection(repoName, selection, cfg, Config{}, func(string, []string) error { return nil }); err != nil {
				t.Fatal(err)
			}

			body, err := os.ReadFile(filepath.Join(dir, fileinfo.RepoPath))
			if err != nil {
				t.Fatal(err)
			}
			marked := containsTrimmedLine(string(body), "# "+fileinfo.AdoptionMarker)
			if marked != tt.adopted {
				t.Fatalf("marked = %v, want %v\n%s", marked, tt.adopted, body)
			}
			if tt.adopted && strings.Contains(string(body), "name: old") {
				t.Fatalf("file was not rewritten to the current template\n%s", body)
			}
			if !tt.adopted && string(body) != tt.content {
				t.Fatalf("file changed to:\n%s", body)
			}

			if tt.checkRetired {
				for _, rel := range retired {
					_, statErr := os.Lstat(filepath.Join(dir, rel))
					removed := os.IsNotExist(statErr)
					if removed != tt.adopted {
						t.Errorf("%s removed = %v, want %v", rel, removed, tt.adopted)
					}
				}
			}
		})
	}
}
