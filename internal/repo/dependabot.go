package repo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

const dependabotTemplateName = "dependabot.yml"

// dependabotEcosystem describes how to find one ecosystem's manifests.
//
// directoriesVar holds either a single repository-relative directory or, for
// github-actions, a JSON list of directories that may contain globs. Manifest
// patterns are matched relative to each configured directory. rootManifests,
// when set, replaces manifests for a directory that resolves to the repository
// root (github-actions keeps workflows under .github/workflows).
type dependabotEcosystem struct {
	name           string
	enabledVar     string
	directoriesVar string
	manifests      []string
	rootManifests  []string
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
		manifests:      []string{"requirements*.txt", "pyproject.toml", "setup.py", "Pipfile"},
	},
	{
		name:           "github-actions",
		enabledVar:     "DEPENDABOT_ACTIONS_ENABLED",
		directoriesVar: "DEPENDABOT_ACTIONS_DIRECTORIES",
		manifests:      []string{"action.yml", "action.yaml"},
		rootManifests:  []string{".github/workflows/*.yml", ".github/workflows/*.yaml"},
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
}

var errNoDependabotEcosystems = errors.New("no Dependabot ecosystems detected")

// DependabotVarsForRepo merges the template variables and adds Dependabot
// ecosystem flags from manifests in the target repo. If detection fails, the
// merged variables without flags are returned with the error, so callers fall
// back to the full historical template output.
func DependabotVarsForRepo(repoDir string, defaultVars map[string]string, overrides map[string]string) (map[string]string, error) {
	data := mergeTemplateVars(defaultVars, overrides)
	detected, err := DependabotEcosystemVars(repoDir, data)
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
	info, err := os.Stat(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect repository %s: %w", repoDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("inspect repository %s: not a directory", repoDir)
	}

	out := copyTemplateVars(vars)

	anyEnabled := false
	for _, ecosystem := range dependabotEcosystems {
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
			if len(ecosystem.rootManifests) > 0 && filepath.Clean(dir) == filepath.Clean(repoRoot) {
				manifests = ecosystem.rootManifests
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
	dirPath := filepath.Join(baseDir, filepath.Dir(manifest))
	namePattern := filepath.Base(manifest)

	resolvedDir, err := resolveRepositoryPath(repoRoot, dirPath)
	if err != nil {
		return false, fmt.Errorf("manifest %q: %w", manifest, err)
	}
	if resolvedDir == "" {
		return false, nil
	}

	entries, err := os.ReadDir(resolvedDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return false, nil
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
	return false, nil
}
