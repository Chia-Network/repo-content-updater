package repo

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/chia-network/repo-content-updater/internal/config"
)

// Default files are adopt-only and are decided per bundle: a default root and
// the companion closure it expands to. The root's requires_paths and adoption
// marker decide for the whole bundle, so companions (which may not be able to
// carry a marker line) are never written without their root, and are kept up
// to date once the root is owned.

// fileState describes what a repo holds at a managed file's repo paths.
type fileState int

const (
	fileAbsent  fileState = iota // nothing at repo_path or any alternate_path
	fileMarked                   // every existing copy carries the adoption marker line
	fileUnowned                  // some existing copy does not carry it
)

// existingFileState inspects fileinfo's repo_path and alternate_paths under dir.
// A file without an adoption marker is unowned whenever any copy exists, and
// anything other than a regular file (a symlink or directory) is never owned,
// so adoption never reads through a link.
func existingFileState(dir string, fileinfo *config.File) (fileState, error) {
	marker := strings.TrimSpace(fileinfo.AdoptionMarker)
	state := fileAbsent
	for _, repoPath := range append([]string{fileinfo.RepoPath}, fileinfo.AlternatePaths...) {
		fullPath := filepath.Join(dir, filepath.FromSlash(repoPath))
		info, err := os.Lstat(fullPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fileAbsent, err
		}
		if marker == "" || !info.Mode().IsRegular() {
			return fileUnowned, nil
		}
		content, err := os.ReadFile(fullPath)
		if err != nil {
			return fileAbsent, err
		}
		if !containsTrimmedLine(string(content), "# "+marker) {
			return fileUnowned, nil
		}
		state = fileMarked
	}
	return state, nil
}

// adoptedDefaultRoots returns, for each default root among files, whether its
// bundle may be written to repoName.
func (c *Content) adoptedDefaultRoots(repoName string, files []config.SelectedFile, cfg *config.Config) (map[string]bool, error) {
	var roots []string
	members := map[string][]*config.File{}
	for _, selected := range files {
		fileinfo := cfg.GetFileInfo(selected.Name)
		if selected.Origin != config.OriginDefault || fileinfo == nil {
			continue
		}
		if _, ok := members[selected.Root]; !ok {
			roots = append(roots, selected.Root)
		}
		members[selected.Root] = append(members[selected.Root], fileinfo)
	}

	adopted := make(map[string]bool, len(roots))
	for _, root := range roots {
		ok, err := defaultBundleAdoptable(repoName, cfg.GetFileInfo(root), members[root])
		if err != nil {
			return nil, err
		}
		adopted[root] = ok
	}
	return adopted, nil
}

// defaultBundleAdoptable applies the adoption rules to one bundle: the root's
// required paths must exist; a root carrying its marker is owned; an unmarked
// root is left alone; an absent root is only created when no companion path
// is already occupied.
func defaultBundleAdoptable(repoName string, root *config.File, members []*config.File) (bool, error) {
	if root == nil {
		return false, nil
	}
	dir := repoDir(repoName)
	missing, err := firstMissingRequiredPath(dir, root.RequiresPaths)
	if err != nil {
		return false, err
	}
	if missing != "" {
		log.Printf("Skipping default %s for %s: required path %s missing\n", root.Name, repoName, missing)
		return false, nil
	}

	state, err := existingFileState(dir, root)
	if err != nil {
		return false, err
	}
	switch state {
	case fileMarked:
		return true, nil
	case fileUnowned:
		log.Printf("Skipping %s for %s: existing file does not carry the adoption marker\n", root.Name, repoName)
		return false, nil
	}

	for _, member := range members {
		if member.Name == root.Name {
			continue
		}
		occupied, err := anyPathExists(dir, member)
		if err != nil {
			return false, err
		}
		if occupied {
			log.Printf("Skipping default %s for %s: companion path for %s already exists\n", root.Name, repoName, member.Name)
			return false, nil
		}
	}
	return true, nil
}

// anyPathExists reports whether anything, including a dangling symlink, sits
// at fileinfo's repo_path or an alternate_path under dir.
func anyPathExists(dir string, fileinfo *config.File) (bool, error) {
	for _, repoPath := range append([]string{fileinfo.RepoPath}, fileinfo.AlternatePaths...) {
		_, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(repoPath)))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		return err == nil, err
	}
	return false, nil
}

// withAdoptionMarker exposes a file's adoption marker to its template as
// ADOPTION_MARKER so rendered output stays adoptable on later runs.
func withAdoptionMarker(vars map[string]string, marker string) map[string]string {
	marker = strings.TrimSpace(marker)
	if marker == "" {
		return vars
	}
	out := copyTemplateVars(vars)
	out[adoptionMarkerVar] = marker
	return out
}

const adoptionMarkerVar = "ADOPTION_MARKER"

const managedFileMarker = "managed by the repo-content-updater"

// containsTrimmedLine reports whether content contains want as a complete line,
// ignoring surrounding whitespace.
func containsTrimmedLine(content, want string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

// requiredPathExists reports whether repoRelPath exists under root. A directory
// only satisfies the requirement when it directly contains a .yml or .yaml file.
func requiredPathExists(root, repoRelPath string) (bool, error) {
	fullPath := filepath.Join(root, filepath.FromSlash(repoRelPath))
	info, err := os.Stat(fullPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return true, nil
	}

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(entry.Name())) {
		case ".yml", ".yaml":
			return true, nil
		}
	}
	return false, nil
}

// firstMissingRequiredPath returns the first requires_paths entry that is not
// satisfied under root, or "" when every entry is satisfied.
func firstMissingRequiredPath(root string, requiredPaths []string) (string, error) {
	for _, requiredPath := range requiredPaths {
		exists, err := requiredPathExists(root, requiredPath)
		if err != nil {
			return "", err
		}
		if !exists {
			return requiredPath, nil
		}
	}
	return "", nil
}
