package repo

import (
	"os"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/chia-network/repo-content-updater/internal/config"
)

// droppedDependabotEcosystems lists, in order, the package ecosystems that an
// existing copy of fileinfo configures and rendered does not. A default
// Dependabot file is only rewritten when this is empty, so adopting a repo
// never removes an ecosystem it already updates. An existing copy that cannot
// be read as YAML keeps its place: its ecosystems cannot be compared.
func droppedDependabotEcosystems(dir string, fileinfo *config.File, rendered []byte) ([]string, error) {
	kept, ok := dependabotEcosystemNames(rendered)
	if !ok {
		return []string{"(rendered configuration)"}, nil
	}
	var dropped []string
	for _, repoPath := range managedPaths(fileinfo) {
		fullPath, info, err := lstatConfined(dir, repoPath)
		if err != nil {
			return nil, err
		}
		if info == nil || !info.Mode().IsRegular() {
			continue
		}
		existing, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, err
		}
		names, ok := dependabotEcosystemNames(existing)
		if !ok {
			return []string{repoPath}, nil
		}
		for _, name := range names {
			if !slices.Contains(kept, name) && !slices.Contains(dropped, name) {
				dropped = append(dropped, name)
			}
		}
	}
	return dropped, nil
}

func dependabotEcosystemNames(raw []byte) ([]string, bool) {
	var doc struct {
		Updates []struct {
			Ecosystem string `yaml:"package-ecosystem"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, false
	}
	names := make([]string, 0, len(doc.Updates))
	for _, update := range doc.Updates {
		names = append(names, update.Ecosystem)
	}
	return names, true
}
