package repo

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
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
// A file without an adoption marker is unowned whenever any copy exists.
// Anything other than a regular file, or a path whose parent is not a real
// directory inside dir, is never owned, so adoption only reads checkout files.
func existingFileState(dir string, fileinfo *config.File) (fileState, error) {
	markers := adoptionMarkerLines(fileinfo)
	state := fileAbsent
	for _, repoPath := range managedPaths(fileinfo) {
		fullPath, info, err := lstatConfined(dir, repoPath)
		if errors.Is(err, errUnconfinedPath) {
			return fileUnowned, nil
		}
		if err != nil {
			return fileAbsent, err
		}
		if info == nil {
			continue
		}
		if len(markers) == 0 || !info.Mode().IsRegular() {
			return fileUnowned, nil
		}
		content, err := os.ReadFile(fullPath)
		if err != nil {
			return fileAbsent, err
		}
		if !containsAnyTrimmedLine(string(content), markers) {
			return fileUnowned, nil
		}
		state = fileMarked
	}
	return state, nil
}

// adoptionMarkerLines returns every marker spelling a file accepts, each as the
// whole-line `# marker` form the template renders, current marker first.
func adoptionMarkerLines(fileinfo *config.File) []string {
	var markers []string
	add := func(marker string) {
		marker = strings.TrimSpace(marker)
		if marker != "" {
			markers = append(markers, "# "+marker)
		}
	}
	add(fileinfo.AdoptionMarker)
	for _, previous := range fileinfo.PreviousAdoptionMarkers {
		add(previous)
	}
	return markers
}

// managedPaths lists fileinfo's repo_path followed by its alternate_paths.
func managedPaths(fileinfo *config.File) []string {
	return append([]string{fileinfo.RepoPath}, fileinfo.AlternatePaths...)
}

// removedPaths lists the paths writing fileinfo deletes: its alternate_paths,
// then its retired_paths.
func removedPaths(fileinfo *config.File) []string {
	return append(slices.Clone(fileinfo.AlternatePaths), fileinfo.RetiredPaths...)
}

// writtenPaths lists every path writing fileinfo touches: its repo_path, then
// the removedPaths it deletes.
func writtenPaths(fileinfo *config.File) []string {
	return append([]string{fileinfo.RepoPath}, removedPaths(fileinfo)...)
}

// adoptableDefaults returns the files of every default bundle that may be
// written to repoName, in bundle order.
func adoptableDefaults(repoName string, bundles []config.DefaultBundle, cfg *config.Config) ([]config.SelectedFile, error) {
	var files []config.SelectedFile
	for _, bundle := range bundles {
		members := make([]*config.File, 0, len(bundle.Files))
		for _, name := range bundle.Files {
			if fileinfo := cfg.GetFileInfo(name); fileinfo != nil {
				members = append(members, fileinfo)
			}
		}
		ok, err := defaultBundleAdoptable(repoName, cfg.GetFileInfo(bundle.Root), members)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		for _, name := range bundle.Files {
			files = append(files, config.SelectedFile{Name: name, Origin: config.OriginDefault})
		}
	}
	return files, nil
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
// at fileinfo's repo_path or an alternate_path under dir. A path that cannot
// be confined to dir counts as occupied.
func anyPathExists(dir string, fileinfo *config.File) (bool, error) {
	for _, repoPath := range managedPaths(fileinfo) {
		_, info, err := lstatConfined(dir, repoPath)
		if errors.Is(err, errUnconfinedPath) {
			return true, nil
		}
		if err != nil || info != nil {
			return info != nil, err
		}
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

// containsAnyTrimmedLine reports whether content contains any of wants as a
// complete line, ignoring surrounding whitespace.
func containsAnyTrimmedLine(content string, wants []string) bool {
	for _, want := range wants {
		if containsTrimmedLine(content, want) {
			return true
		}
	}
	return false
}

// requiredPathExists reports whether repoRelPath exists under root as a
// regular file, or as a real directory that directly contains a regular .yml
// or .yaml file. Links, and paths below a linked parent, never satisfy it.
func requiredPathExists(root, repoRelPath string) (bool, error) {
	fullPath, info, err := lstatConfined(root, repoRelPath)
	if errors.Is(err, errUnconfinedPath) {
		return false, nil
	}
	if err != nil || info == nil {
		return false, err
	}
	if info.Mode().IsRegular() {
		return true, nil
	}
	if !info.IsDir() {
		return false, nil
	}

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
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
