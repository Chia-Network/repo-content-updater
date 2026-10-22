package repo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chia-network/repo-content-updater/internal/config"
)

func TestManagedWritePathStaysInsideRepo(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir()

	t.Run("plain path", func(t *testing.T) {
		got, err := managedWritePath(repo, ".github/new/file.yml")
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(repo, ".github", "new", "file.yml"); got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
	})

	t.Run("symlinked parent leading outside is rejected", func(t *testing.T) {
		if err := os.Symlink(outside, filepath.Join(repo, "escape")); err != nil {
			t.Fatal(err)
		}
		if _, err := managedWritePath(repo, "escape/sub/file.yml"); err == nil {
			t.Fatal("expected an error for a symlinked parent outside the repo")
		}
	})

	t.Run("symlink at the path is replaced, not followed", func(t *testing.T) {
		victim := filepath.Join(outside, "victim")
		if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(repo, "link.yml")
		if err := os.Symlink(victim, link); err != nil {
			t.Fatal(err)
		}
		got, err := managedWritePath(repo, "link.yml")
		if err != nil {
			t.Fatal(err)
		}
		if err := writeManagedContent(got, []byte("managed\n")); err != nil {
			t.Fatal(err)
		}
		if body, _ := os.ReadFile(victim); string(body) != "keep" {
			t.Fatalf("write followed the symlink; victim = %q", body)
		}
		if info, err := os.Lstat(link); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("link.yml is not a regular file: %v %v", info, err)
		}
	})

	t.Run("dot-dot path is rejected", func(t *testing.T) {
		if _, err := managedWritePath(repo, "../x.yml"); err == nil {
			t.Fatal("expected an error for ../")
		}
	})
}

func TestAdoptionNeverReadsThroughSymlinks(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "marked.yml")
	fileinfo := &config.File{RepoPath: "root.yml", AdoptionMarker: "test:marker"}
	if err := os.WriteFile(outside, []byte("# test:marker\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "root.yml")); err != nil {
		t.Fatal(err)
	}
	state, err := existingFileState(dir, fileinfo)
	if err != nil {
		t.Fatal(err)
	}
	if state != fileUnowned {
		t.Fatalf("symlinked marked file state = %d, want unowned", state)
	}

	if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, "dangling.js")); err != nil {
		t.Fatal(err)
	}
	occupied, err := anyPathExists(dir, &config.File{RepoPath: "dangling.js"})
	if err != nil {
		t.Fatal(err)
	}
	if !occupied {
		t.Fatal("a dangling symlink must occupy a companion path")
	}
}
