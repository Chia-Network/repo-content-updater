package repo

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// errUnconfinedPath marks a repository-relative path that cannot be used
// without leaving the checkout: it climbs above the root, or one of its
// existing parent directories is not a real directory.
var errUnconfinedPath = errors.New("path is not confined to the repository")

// confinedPath is the one place managed-file code turns a repository-relative
// path into a filesystem path, for reads, deletes and writes alike. Every
// existing parent between repoRoot and the path must be a real directory, so
// nothing below it can resolve elsewhere. The final component is returned
// unresolved; callers Lstat it and never follow a link there.
func confinedPath(repoRoot, repoRelPath string) (string, error) {
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		return "", err
	}
	target := filepath.Join(root, filepath.FromSlash(repoRelPath))
	if target == root || escapesRepository(root, target) {
		return "", fmt.Errorf("%s: %w", repoRelPath, errUnconfinedPath)
	}
	rel, err := filepath.Rel(root, filepath.Dir(target))
	if err != nil {
		return "", err
	}
	if rel == "." {
		return target, nil
	}
	dir := root
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		dir = filepath.Join(dir, part)
		info, err := os.Lstat(dir)
		if errors.Is(err, fs.ErrNotExist) {
			break
		}
		if err != nil {
			return "", err
		}
		if !info.IsDir() {
			return "", fmt.Errorf("%s: %w", repoRelPath, errUnconfinedPath)
		}
	}
	return target, nil
}

// lstatConfined confines repoRelPath and Lstats it. A missing path returns a
// nil FileInfo and no error.
func lstatConfined(repoRoot, repoRelPath string) (string, fs.FileInfo, error) {
	target, err := confinedPath(repoRoot, repoRelPath)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Lstat(target)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return target, nil, nil
	}
	return target, info, err
}

// managedWritePath returns where repoRelPath is written under repoRoot. A
// link at the path itself is removed so the managed content replaces it.
func managedWritePath(repoRoot, repoRelPath string) (string, error) {
	target, info, err := lstatConfined(repoRoot, repoRelPath)
	if err != nil {
		return "", err
	}
	if info != nil && info.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(target); err != nil {
			return "", err
		}
	}
	return target, nil
}

// removeConfined deletes each repository-relative path that exists. Every path
// is confined before anything is removed, so one bad path removes nothing.
func removeConfined(repoRoot string, repoRelPaths []string) error {
	targets := make([]string, 0, len(repoRelPaths))
	for _, repoRelPath := range repoRelPaths {
		target, err := confinedPath(repoRoot, repoRelPath)
		if err != nil {
			return err
		}
		targets = append(targets, target)
	}
	for _, target := range targets {
		if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}
