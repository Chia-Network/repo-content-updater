package repo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chia-network/repo-content-updater/internal/config"
)

// TestDependencyReviewAdoptsEarlierHeaderMarkers covers repos whose
// dependency-review.yml was rendered before the current adoption marker.
func TestDependencyReviewAdoptsEarlierHeaderMarkers(t *testing.T) {
	cfg := loadDependabotTestConfig(t)
	templates, err := filepath.Abs(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	content := &Content{templates: templates}
	depReview := cfg.GetFileInfo("dep-review")
	selection := config.ManagedFileSelection{Defaults: []config.DefaultBundle{{
		Root:  "dep-review",
		Files: []string{"dep-review"},
	}}}
	retired := []string{
		".github/workflows/dependency-cursor-review.yml",
		".github/scripts/malware_verdict_formatter.py",
	}

	const (
		firstHeader  = "# Managed by repo-content-updater"
		secondHeader = "# This file is managed by the repo-content-updater project. Manual changes here will result in a PR to bring back"
	)

	tests := []struct {
		name    string
		content string
		adopted bool
	}{
		{name: "first earlier header", content: firstHeader + "\nname: old\n", adopted: true},
		{name: "second earlier header", content: secondHeader + "\nname: old\n", adopted: true},
		{name: "hand-written file", content: "name: old\n"},
		{name: "earlier header mid-line", content: "foo # Managed by repo-content-updater\nname: old\n"},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoName := fmt.Sprintf("dep-review-%d", i)
			dir := repoDir(repoName)
			writeDependabotTestFile(t, dir, depReview.RepoPath, tt.content)
			for _, rel := range retired {
				writeDependabotTestFile(t, dir, rel, "legacy\n")
			}

			if err := content.applySelection(repoName, selection, cfg, Config{}, func(string, []string) error { return nil }); err != nil {
				t.Fatal(err)
			}

			body, err := os.ReadFile(filepath.Join(dir, depReview.RepoPath))
			if err != nil {
				t.Fatal(err)
			}
			marked := containsTrimmedLine(string(body), "# "+depReview.AdoptionMarker)
			if marked != tt.adopted {
				t.Fatalf("marked = %v, want %v\n%s", marked, tt.adopted, body)
			}
			if tt.adopted && strings.Contains(string(body), "name: old") {
				t.Fatalf("file was not rewritten to the current template\n%s", body)
			}
			if !tt.adopted && string(body) != tt.content {
				t.Fatalf("file changed to:\n%s", body)
			}

			for _, rel := range retired {
				_, statErr := os.Lstat(filepath.Join(dir, rel))
				removed := os.IsNotExist(statErr)
				if removed != tt.adopted {
					t.Errorf("%s removed = %v, want %v", rel, removed, tt.adopted)
				}
			}
		})
	}
}
