package repo

import (
	"bytes"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/chia-network/repo-content-updater/internal/config"
)

// actionsReviewers are the reviewers every github-actions block requests.
var actionsReviewers = []string{"cameroncooper", "emlowe"}

// mergeDependabotConfig folds the update entries of an existing default
// Dependabot file into rendered so adopting a repo never removes an
// ecosystem or directory it already updates. Entries are keyed by ecosystem
// plus directories: a directory the rendered file already covers for that
// ecosystem is taken from the rendered entry, and each remaining
// (ecosystem, directories) key from the existing file is kept as one block.
// Every github-actions block is weekly with actionsReviewers. ok is false when
// either file cannot be read as YAML; the existing file then stays as it is.
func mergeDependabotConfig(dir string, fileinfo *config.File, rendered []byte) ([]byte, bool, error) {
	var doc yaml.Node
	updates, ok := dependabotUpdates(rendered, &doc)
	if !ok {
		return nil, false, nil
	}
	covered := map[string][]string{}
	for _, entry := range updates.Content {
		eco, dirs := entryKey(entry)
		covered[eco] = append(covered[eco], dirs...)
	}
	seen := map[string]bool{}
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
			if keep := uncoveredEntry(entry, covered, seen); keep != nil {
				updates.Content = append(updates.Content, keep)
				appended = true
			}
		}
	}
	if !appended {
		return rendered, true, nil
	}
	for _, entry := range updates.Content {
		if eco, _ := entryKey(entry); eco == "github-actions" {
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
// yet hold for its ecosystem, or nil when nothing is left or its key was
// already kept. An entry without directories is kept only when its
// ecosystem is not covered at all.
func uncoveredEntry(entry *yaml.Node, covered map[string][]string, seen map[string]bool) *yaml.Node {
	eco, dirs := entryKey(entry)
	var rest []string
	for _, d := range dirs {
		if !slices.Contains(covered[eco], d) && !slices.Contains(rest, d) {
			rest = append(rest, d)
		}
	}
	_, ecoCovered := covered[eco]
	if len(rest) == 0 && (len(dirs) > 0 || ecoCovered) {
		return nil
	}
	slices.Sort(rest)
	key := eco + "\x00" + strings.Join(rest, "\x00")
	if seen[key] {
		return nil
	}
	seen[key] = true
	covered[eco] = append(covered[eco], rest...)
	if len(rest) != len(dirs) {
		setDirectories(entry, rest)
	}
	return entry
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

// entryKey returns an update entry's ecosystem and its normalized
// directories from either directory or directories.
func entryKey(entry *yaml.Node) (string, []string) {
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
	return eco, dirs
}

func normalizeDependabotDir(d string) string {
	return "/" + strings.Trim(d, "/")
}

func setDirectories(entry *yaml.Node, dirs []string) {
	removeMapKey(entry, "directory")
	removeMapKey(entry, "directories")
	if len(dirs) == 1 {
		setMapValue(entry, "directory", scalarNode(dirs[0]))
		return
	}
	setMapValue(entry, "directories", stringSeq(dirs))
}

func setActionsDefaults(entry *yaml.Node) {
	schedule := mapValue(entry, "schedule")
	if schedule == nil || schedule.Kind != yaml.MappingNode {
		schedule = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setMapValue(entry, "schedule", schedule)
	}
	setMapValue(schedule, "interval", scalarNode("weekly"))
	setMapValue(entry, "reviewers", stringSeq(actionsReviewers))
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

func dependabotEcosystemNames(raw []byte) ([]string, bool) {
	var doc yaml.Node
	updates, ok := dependabotUpdates(raw, &doc)
	if !ok {
		return nil, false
	}
	names := make([]string, 0, len(updates.Content))
	for _, entry := range updates.Content {
		eco, _ := entryKey(entry)
		names = append(names, eco)
	}
	return names, true
}
