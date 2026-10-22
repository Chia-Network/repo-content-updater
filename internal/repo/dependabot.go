package repo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

const dependabotTemplateName = "dependabot.yml"

// dependabotEcosystem describes how to find one ecosystem's manifests.
//
// directoriesVar holds either a single repository-relative directory or, for
// github-actions, a JSON list of directories that may contain globs. Manifest
// patterns are matched relative to each configured directory.
// nonRootManifests, when set, replaces manifests for directories below the
// repository root. rootExtraManifests, when set, are added to manifests for a
// directory that resolves to the repository root (github-actions additionally
// checks workflows under .github/workflows).
//
// discover marks ecosystems whose manifests Dependabot does not look for
// below the configured directory. Unless the repo pins directoriesVar, their
// directories are discovered from the whole tree and written back to
// directoriesVar as a JSON list. A directory matching rootCovers at the root
// stands for the whole tree (a NuGet solution lists its projects).
type dependabotEcosystem struct {
	name               string
	enabledVar         string
	directoriesVar     string
	manifests          []string
	nonRootManifests   []string
	rootExtraManifests []string
	discover           bool
	rootCovers         []string
}

var dependabotEcosystems = []dependabotEcosystem{
	{
		name:           "gomod",
		enabledVar:     "DEPENDABOT_GOMOD_ENABLED",
		directoriesVar: "DEPENDABOT_GOMOD_DIRECTORY",
		manifests:      []string{"go.mod"},
	},
	{
		name:           "pip",
		enabledVar:     "DEPENDABOT_PIP_ENABLED",
		directoriesVar: "DEPENDABOT_PIP_DIRECTORY",
		manifests: []string{
			"*requirements*.txt",
			"*requirements*.in",
			"pyproject.toml",
			"setup.py",
			"setup.cfg",
			"Pipfile",
			"*/*requirements*.txt",
			"*/*requirements*.in",
			"*requirements*/*.txt",
			"*requirements*/*.in",
		},
	},
	{
		name:               "github-actions",
		enabledVar:         "DEPENDABOT_ACTIONS_ENABLED",
		directoriesVar:     "DEPENDABOT_ACTIONS_DIRECTORIES",
		manifests:          []string{"action.yml", "action.yaml"},
		nonRootManifests:   []string{"*.yml", "*.yaml"},
		rootExtraManifests: []string{".github/workflows/*.yml", ".github/workflows/*.yaml"},
	},
	{
		name:           "npm",
		enabledVar:     "DEPENDABOT_NPM_ENABLED",
		directoriesVar: "DEPENDABOT_NPM_DIRECTORY",
		manifests:      []string{"package.json"},
	},
	{
		name:           "cargo",
		enabledVar:     "DEPENDABOT_CARGO_ENABLED",
		directoriesVar: "DEPENDABOT_CARGO_DIRECTORY",
		manifests:      []string{"Cargo.toml"},
	},
	{
		name:           "swift",
		enabledVar:     "DEPENDABOT_SWIFT_ENABLED",
		directoriesVar: "DEPENDABOT_SWIFT_DIRECTORY",
		manifests:      []string{"Package.swift"},
	},
	{
		name:           "docker",
		enabledVar:     "DEPENDABOT_DOCKER_ENABLED",
		directoriesVar: "DEPENDABOT_DOCKER_DIRECTORIES",
		manifests:      []string{"Dockerfile", "Dockerfile.*", "*.dockerfile"},
		discover:       true,
	},
	{
		name:           "terraform",
		enabledVar:     "DEPENDABOT_TERRAFORM_ENABLED",
		directoriesVar: "DEPENDABOT_TERRAFORM_DIRECTORIES",
		manifests:      []string{"*.tf", "*.tf.json", ".terraform.lock.hcl"},
		discover:       true,
	},
	{
		name:           "nuget",
		enabledVar:     "DEPENDABOT_NUGET_ENABLED",
		directoriesVar: "DEPENDABOT_NUGET_DIRECTORIES",
		manifests: []string{
			"*.csproj",
			"*.fsproj",
			"*.vbproj",
			"*.sln",
			"packages.config",
			"Directory.Packages.props",
		},
		discover:   true,
		rootCovers: []string{"*.sln"},
	},
}

var errNoDependabotEcosystems = errors.New("no Dependabot ecosystems detected")

// DependabotVarsForRepo merges the template variables and adds Dependabot
// ecosystem flags from manifests in the target repo. If detection fails, the
// merged variables without flags are returned with the error, so callers fall
// back to the full historical template output. Directories of discovered
// ecosystems come from the tree unless overrides pins them.
func DependabotVarsForRepo(repoDir string, defaultVars map[string]string, overrides map[string]string) (map[string]string, error) {
	data := mergeTemplateVars(defaultVars, overrides)
	detectInput := copyTemplateVars(data)
	for _, ecosystem := range dependabotEcosystems {
		if _, pinned := overrides[ecosystem.directoriesVar]; ecosystem.discover && !pinned {
			delete(detectInput, ecosystem.directoriesVar)
		}
	}
	detected, err := DependabotEcosystemVars(repoDir, detectInput)
	if err != nil {
		return templateVarsWithoutDependabotFlags(data), err
	}
	return detected, nil
}

// DependabotEcosystemVars returns a copy of vars with an enabled flag for each
// ecosystem in the managed Dependabot template. Each manifest is looked up in
// the directory configured for that ecosystem, so a repo that pins a nested
// Dependabot directory is inspected where Dependabot will actually run.
//
// Missing directories and ENOTDIR are treated as absent. A real inspection
// error for one ecosystem keeps that ecosystem enabled (today's behavior)
// without discarding detection for the others. If no ecosystem can be enabled,
// the vars without flags are returned with errNoDependabotEcosystems so callers
// keep the full historical template output.
func DependabotEcosystemVars(repoDir string, vars map[string]string) (map[string]string, error) {
	repoRoot, err := filepath.EvalSymlinks(repoDir)
	if err != nil {
		return nil, fmt.Errorf("resolve repository %s: %w", repoDir, err)
	}
	repoRoot, err = filepath.Abs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve repository %s: %w", repoDir, err)
	}
	info, err := os.Stat(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect repository %s: %w", repoDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("inspect repository %s: not a directory", repoDir)
	}

	out := copyTemplateVars(vars)
	var unpinned []dependabotEcosystem
	for _, ecosystem := range dependabotEcosystems {
		if ecosystem.discover && strings.TrimSpace(vars[ecosystem.directoriesVar]) == "" {
			unpinned = append(unpinned, ecosystem)
		}
	}
	discovered, err := discoverManifestDirectories(repoRoot, unpinned)
	if err != nil {
		return nil, fmt.Errorf("discover manifests: %w", err)
	}

	anyEnabled := false
	for _, ecosystem := range dependabotEcosystems {
		if dirs, ok := discovered[ecosystem.name]; ok {
			encoded, _ := json.Marshal(dirs)
			out[ecosystem.directoriesVar] = string(encoded)
			out[ecosystem.enabledVar] = "0"
			if len(dirs) > 0 {
				out[ecosystem.enabledVar] = "1"
				anyEnabled = true
			}
			continue
		}
		present, err := dependabotEcosystemPresent(repoRoot, ecosystem, vars)
		switch {
		case err != nil:
			log.Printf("Error detecting %s manifests; keeping it enabled: %v\n", ecosystem.name, err)
			out[ecosystem.enabledVar] = "1"
			anyEnabled = true
		case present:
			out[ecosystem.enabledVar] = "1"
			anyEnabled = true
		default:
			out[ecosystem.enabledVar] = "0"
		}
	}
	if !anyEnabled {
		return templateVarsWithoutDependabotFlags(vars), errNoDependabotEcosystems
	}
	return out, nil
}

func copyTemplateVars(vars map[string]string) map[string]string {
	out := make(map[string]string, len(vars))
	for key, value := range vars {
		out[key] = value
	}
	return out
}

func templateVarsWithoutDependabotFlags(vars map[string]string) map[string]string {
	out := copyTemplateVars(vars)
	for _, ecosystem := range dependabotEcosystems {
		delete(out, ecosystem.enabledVar)
	}
	return out
}

func dependabotEcosystemPresent(repoRoot string, ecosystem dependabotEcosystem, vars map[string]string) (bool, error) {
	directories, err := parseDependabotDirectories(vars[ecosystem.directoriesVar])
	if err != nil {
		return false, fmt.Errorf("%s: %w", ecosystem.directoriesVar, err)
	}

	for _, raw := range directories {
		resolvedDirs, err := expandDependabotDirectory(repoRoot, raw)
		if err != nil {
			return false, err
		}
		for _, dir := range resolvedDirs {
			manifests := ecosystem.manifests
			if filepath.Clean(dir) == filepath.Clean(repoRoot) {
				if len(ecosystem.rootExtraManifests) > 0 {
					manifests = slices.Concat(manifests, ecosystem.rootExtraManifests)
				}
			} else if len(ecosystem.nonRootManifests) > 0 {
				manifests = ecosystem.nonRootManifests
			}
			present, err := dependabotManifestsPresent(repoRoot, dir, manifests)
			if err != nil {
				return false, err
			}
			if present {
				return true, nil
			}
		}
	}
	return false, nil
}

// discoveryPrunedDirs are never searched for discovered manifests.
var discoveryPrunedDirs = map[string]bool{".git": true, "node_modules": true}

// discoverManifestDirectories walks repoRoot once and returns, for each
// ecosystem, the sorted "/"-rooted directories that directly hold a regular
// file matching its manifests. A root file matching rootCovers maps that
// ecosystem to ["/"]. Links are not followed.
func discoverManifestDirectories(repoRoot string, ecosystems []dependabotEcosystem) (map[string][]string, error) {
	found := make(map[string]map[string]bool, len(ecosystems))
	coveredAtRoot := map[string]bool{}
	for _, ecosystem := range ecosystems {
		found[ecosystem.name] = map[string]bool{}
	}
	if len(ecosystems) > 0 {
		err := filepath.WalkDir(repoRoot, func(current string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if current != repoRoot && discoveryPrunedDirs[entry.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(repoRoot, filepath.Dir(current))
			if err != nil {
				return err
			}
			for _, ecosystem := range ecosystems {
				if rel == "." && matchesAnyPattern(ecosystem.rootCovers, entry.Name()) {
					coveredAtRoot[ecosystem.name] = true
				}
				if matchesAnyPattern(ecosystem.manifests, entry.Name()) {
					found[ecosystem.name][path.Join("/", filepath.ToSlash(rel))] = true
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	out := make(map[string][]string, len(found))
	for name, dirs := range found {
		if coveredAtRoot[name] {
			out[name] = []string{"/"}
			continue
		}
		out[name] = slices.Sorted(maps.Keys(dirs))
	}
	return out, nil
}

func matchesAnyPattern(patterns []string, name string) bool {
	return slices.ContainsFunc(patterns, func(pattern string) bool {
		// Manifest patterns are constants, so Match cannot fail here.
		matched, _ := filepath.Match(pattern, name)
		return matched
	})
}

func parseDependabotDirectories(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{"/"}, nil
	}
	if !strings.HasPrefix(raw, "[") {
		return []string{raw}, nil
	}
	var directories []string
	if err := json.Unmarshal([]byte(raw), &directories); err != nil {
		return nil, err
	}
	if len(directories) == 0 {
		return []string{"/"}, nil
	}
	return directories, nil
}

func expandDependabotDirectory(repoRoot, raw string) ([]string, error) {
	cleaned := cleanRepositoryPath(raw)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return nil, fmt.Errorf("configured directory %q escapes the repository", raw)
	}

	if !strings.ContainsAny(cleaned, "*?[") {
		resolved, err := resolveRepositoryPath(repoRoot, cleaned)
		if err != nil {
			return nil, fmt.Errorf("configured directory %q: %w", raw, err)
		}
		if resolved == "" {
			return nil, nil
		}
		return []string{resolved}, nil
	}

	matches, err := fs.Glob(os.DirFS(repoRoot), cleaned)
	if err != nil {
		return nil, err
	}
	dirs := make([]string, 0, len(matches))
	for _, match := range matches {
		resolved, err := resolveRepositoryPath(repoRoot, match)
		if err != nil {
			return nil, fmt.Errorf("configured directory %q: %w", raw, err)
		}
		if resolved != "" {
			dirs = append(dirs, resolved)
		}
	}
	return dirs, nil
}

func cleanRepositoryPath(raw string) string {
	cleaned := strings.TrimLeft(filepath.ToSlash(strings.TrimSpace(raw)), "/")
	if cleaned == "" {
		return "."
	}
	return path.Clean(cleaned)
}

// resolveRepositoryPath resolves target (relative to repoRoot or absolute).
// Missing paths and ENOTDIR return an empty path with no error. Paths outside
// the repository, including through symlinks, return an error.
func resolveRepositoryPath(repoRoot, target string) (string, error) {
	if !filepath.IsAbs(target) {
		target = filepath.Join(repoRoot, filepath.FromSlash(target))
	}
	target = filepath.Clean(target)

	if escapesRepository(repoRoot, target) {
		return "", fmt.Errorf("%s escapes the repository", target)
	}

	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return "", nil
		}
		return "", err
	}
	if escapesRepository(repoRoot, resolved) {
		return "", fmt.Errorf("%s escapes the repository", resolved)
	}
	return resolved, nil
}

func escapesRepository(repoRoot, target string) bool {
	rel, err := filepath.Rel(repoRoot, target)
	if err != nil {
		return true
	}
	return rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func dependabotManifestsPresent(repoRoot, baseDir string, manifests []string) (bool, error) {
	for _, manifest := range manifests {
		present, err := dependabotManifestPresent(repoRoot, baseDir, manifest)
		if err != nil || present {
			return present, err
		}
	}
	return false, nil
}

func dependabotManifestPresent(repoRoot, baseDir, manifest string) (bool, error) {
	manifest = filepath.FromSlash(manifest)
	dirPattern := filepath.Dir(manifest)
	namePattern := filepath.Base(manifest)

	dirs, err := manifestDirectories(repoRoot, baseDir, dirPattern)
	if err != nil {
		return false, fmt.Errorf("manifest %q: %w", manifest, err)
	}
	for _, resolvedDir := range dirs {
		entries, err := os.ReadDir(resolvedDir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
				continue
			}
			return false, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			// Manifest patterns are constants, so Match cannot fail here.
			matched, _ := filepath.Match(namePattern, entry.Name())
			if !matched {
				continue
			}
			resolved, err := resolveRepositoryPath(repoRoot, filepath.Join(resolvedDir, entry.Name()))
			if err != nil {
				return false, fmt.Errorf("manifest %q: %w", filepath.Join(manifest, entry.Name()), err)
			}
			if resolved != "" {
				return true, nil
			}
		}
	}
	return false, nil
}

func manifestDirectories(repoRoot, baseDir, dirPattern string) ([]string, error) {
	if !strings.ContainsAny(dirPattern, "*?[") {
		resolved, err := resolveRepositoryPath(repoRoot, filepath.Join(baseDir, dirPattern))
		if err != nil {
			return nil, err
		}
		if resolved == "" {
			return nil, nil
		}
		return []string{resolved}, nil
	}

	matches, err := fs.Glob(os.DirFS(baseDir), filepath.ToSlash(dirPattern))
	if err != nil {
		return nil, err
	}
	dirs := make([]string, 0, len(matches))
	for _, match := range matches {
		resolved, err := resolveRepositoryPath(repoRoot, filepath.Join(baseDir, filepath.FromSlash(match)))
		if err != nil {
			return nil, err
		}
		if resolved != "" {
			dirs = append(dirs, resolved)
		}
	}
	return dirs, nil
}
