package repo

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/chia-network/repo-content-updater/internal/config"
)

// errConflictingDependabotEntries marks two existing update entries that share
// an ecosystem and directories key but configure them differently. The merge
// leaves the existing file untouched rather than silently dropping one.
var errConflictingDependabotEntries = errors.New("conflicting Dependabot update entries share a key")

// mergeDependabotConfig folds the update entries of an existing default
// Dependabot file into rendered so adopting a repo never removes an
// ecosystem, directory or target branch it already updates. Entries are keyed
// by ecosystem, target-branch and directories: a directory the rendered file
// already covers for that ecosystem (without a target-branch) is taken from
// the rendered entry, and each remaining key from the existing file is kept
// as one block. Identical duplicate blocks collapse; two blocks that share a
// key but configure it differently abort the merge with
// errConflictingDependabotEntries. Every github-actions block stays weekly.
// ok is false when either file cannot be read as YAML; the existing file then
// stays as it is.
func mergeDependabotConfig(dir string, fileinfo *config.File, rendered []byte) ([]byte, bool, error) {
	var doc yaml.Node
	updates, ok := dependabotUpdates(rendered, &doc)
	if !ok {
		return nil, false, nil
	}
	covered := map[string][]string{}
	for _, entry := range updates.Content {
		eco, dirs, targetBranch := entryKey(entry)
		if targetBranch != "" {
			continue
		}
		covered[eco] = append(covered[eco], dirs...)
	}
	seen := map[string]string{}
	appended := false
	for _, repoPath := range managedPaths(fileinfo) {
		existing, err := readRegularConfined(dir, repoPath)
		if err != nil {
			return nil, false, err
		}
		if existing == nil {
			continue
		}
		var old yaml.Node
		oldUpdates, ok := dependabotUpdates(existing, &old)
		if !ok {
			return nil, false, nil
		}
		for _, entry := range oldUpdates.Content {
			keep, err := uncoveredEntry(entry, covered, seen)
			if err != nil {
				return nil, false, err
			}
			if keep != nil {
				updates.Content = append(updates.Content, keep)
				appended = true
			}
		}
	}
	if !appended {
		return rendered, true, nil
	}
	for _, entry := range updates.Content {
		if eco, _, _ := entryKey(entry); eco == "github-actions" {
			setActionsDefaults(entry)
		}
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, false, err
	}
	return out.Bytes(), true, enc.Close()
}

// readRegularConfined returns the bytes of repoPath inside dir, or nil when
// it is absent or not a regular file.
func readRegularConfined(dir, repoPath string) ([]byte, error) {
	fullPath, info, err := lstatConfined(dir, repoPath)
	if err != nil || info == nil || !info.Mode().IsRegular() {
		return nil, err
	}
	return os.ReadFile(fullPath)
}

// uncoveredEntry returns entry narrowed to the directories covered does not
// yet hold for its ecosystem, or nil when nothing is left. Only an entry
// without a target-branch counts as covered; a target-branch entry updates a
// non-default branch the rendered file never covers, so it is always kept
// whole. An entry without directories is kept only when its ecosystem is not
// covered at all. Two entries sharing an ecosystem, target-branch and
// directories key collapse only when they are identical; differing settings
// return errConflictingDependabotEntries so the merge leaves the existing
// file untouched.
func uncoveredEntry(entry *yaml.Node, covered map[string][]string, seen map[string]string) (*yaml.Node, error) {
	eco, dirs, targetBranch := entryKey(entry)
	key := dependabotEntryKey(eco, dirs, targetBranch)
	if previous, ok := seen[key]; ok {
		if previous == encodeDependabotEntry(entry) {
			return nil, nil
		}
		return nil, errConflictingDependabotEntries
	}
	if targetBranch != "" {
		// A target-branch entry updates a non-default branch the rendered
		// file never covers; keep it whole without touching covered.
		seen[key] = encodeDependabotEntry(entry)
		return entry, nil
	}
	rest := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if !slices.Contains(covered[eco], d) && !slices.Contains(rest, d) {
			rest = append(rest, d)
		}
	}
	_, ecoCovered := covered[eco]
	if len(rest) == 0 && (len(dirs) > 0 || ecoCovered) {
		return nil, nil
	}
	slices.Sort(rest)
	seen[key] = encodeDependabotEntry(entry)
	covered[eco] = append(covered[eco], rest...)
	if len(rest) != len(dirs) {
		setDirectories(entry, rest)
	}
	return entry, nil
}

// dependabotEntryKey is the ecosystem plus target-branch plus sorted
// normalized directories.
func dependabotEntryKey(eco string, dirs []string, targetBranch string) string {
	sorted := slices.Clone(dirs)
	slices.Sort(sorted)
	return eco + "\x00" + targetBranch + "\x00" + strings.Join(sorted, "\x00")
}

// encodeDependabotEntry renders one update entry back to YAML for comparison.
func encodeDependabotEntry(entry *yaml.Node) string {
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(entry); err != nil {
		return ""
	}
	_ = enc.Close()
	return out.String()
}

// dependabotUpdates decodes raw into doc and returns its updates sequence.
func dependabotUpdates(raw []byte, doc *yaml.Node) (*yaml.Node, bool) {
	if yaml.Unmarshal(raw, doc) != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, false
	}
	updates := mapValue(doc.Content[0], "updates")
	if updates == nil || updates.Kind != yaml.SequenceNode {
		return nil, false
	}
	for _, entry := range updates.Content {
		if entry.Kind != yaml.MappingNode {
			return nil, false
		}
	}
	return updates, true
}

// entryKey returns an update entry's ecosystem, its normalized directories
// from either directory or directories (["/"] when neither is set), and its
// target-branch ("" when it updates the default branch).
func entryKey(entry *yaml.Node) (string, []string, string) {
	var eco string
	if node := mapValue(entry, "package-ecosystem"); node != nil {
		eco = node.Value
	}
	var dirs []string
	if node := mapValue(entry, "directory"); node != nil && node.Kind == yaml.ScalarNode {
		dirs = append(dirs, normalizeDependabotDir(node.Value))
	}
	if node := mapValue(entry, "directories"); node != nil {
		for _, item := range node.Content {
			dirs = append(dirs, normalizeDependabotDir(item.Value))
		}
	}
	if len(dirs) == 0 {
		dirs = []string{"/"}
	}
	var targetBranch string
	if node := mapValue(entry, "target-branch"); node != nil && node.Kind == yaml.ScalarNode {
		targetBranch = strings.TrimSpace(node.Value)
	}
	return eco, dirs, targetBranch
}

func normalizeDependabotDir(d string) string {
	return "/" + strings.Trim(d, "/")
}

func setDirectories(entry *yaml.Node, dirs []string) {
	removeMapKey(entry, "directory")
	removeMapKey(entry, "directories")
	setMapValue(entry, "directories", stringSeq(dirs))
}

// setActionsDefaults keeps a github-actions block on a weekly interval. Its
// reviewers are left alone: the rendered template sets them and merged blocks
// keep their own.
func setActionsDefaults(entry *yaml.Node) {
	schedule := mapValue(entry, "schedule")
	if schedule == nil || schedule.Kind != yaml.MappingNode {
		schedule = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setMapValue(entry, "schedule", schedule)
	}
	setMapValue(schedule, "interval", scalarNode("weekly"))
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func setMapValue(m *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = value
			return
		}
	}
	m.Content = append(m.Content, scalarNode(key), value)
}

func removeMapKey(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = slices.Delete(m.Content, i, i+2)
			return
		}
	}
}

func scalarNode(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
}

func stringSeq(values []string) *yaml.Node {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, v := range values {
		seq.Content = append(seq.Content, scalarNode(v))
	}
	return seq
}

// pruneDependabotRegistries drops top-level registries no update block
// references, so a repo without pip does not carry the python-index entries.
// Content that is not readable as a Dependabot file is returned unchanged.
func pruneDependabotRegistries(raw []byte) ([]byte, error) {
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return raw, nil
	}
	root := doc.Content[0]
	registries := mapValue(root, "registries")
	if registries == nil || registries.Kind != yaml.MappingNode {
		return raw, nil
	}
	referenced := map[string]bool{}
	if updates := mapValue(root, "updates"); updates != nil && updates.Kind == yaml.SequenceNode {
		for _, entry := range updates.Content {
			if entry.Kind != yaml.MappingNode {
				continue
			}
			if refs := mapValue(entry, "registries"); refs != nil && refs.Kind == yaml.SequenceNode {
				for _, item := range refs.Content {
					referenced[item.Value] = true
				}
			}
		}
	}
	var kept []*yaml.Node
	for i := 0; i+1 < len(registries.Content); i += 2 {
		if referenced[registries.Content[i].Value] {
			kept = append(kept, registries.Content[i], registries.Content[i+1])
		}
	}
	if len(kept) == len(registries.Content) {
		return raw, nil
	}
	if len(kept) == 0 {
		removeMapKey(root, "registries")
	} else {
		registries.Content = kept
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return raw, err
	}
	return out.Bytes(), enc.Close()
}
