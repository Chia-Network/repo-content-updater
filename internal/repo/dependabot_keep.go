package repo

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/chia-network/repo-content-updater/internal/config"
)

// errConflictingDependabotEntries marks existing update entries or registries
// that configure the same thing differently. Merging would silently drop one,
// so the existing file is kept.
var errConflictingDependabotEntries = fmt.Errorf("%w: conflicting Dependabot configuration", errSkipManagedFile)

// postRenderDependabot finishes a rendered Dependabot file: a default one
// (isDefault) folds in what its existing copy configures (see
// mergeExistingDependabot), then registries no update entry references are
// pruned. Pruning after the merge keeps a registry only a merged entry uses.
// The document is encoded once, and only when something changed. A default
// that must keep its existing file returns an error wrapping errSkipManagedFile.
func postRenderDependabot(dir string, isDefault bool, fileinfo *config.File, rendered []byte) ([]byte, error) {
	var doc yaml.Node
	updates, ok := dependabotUpdates(rendered, &doc)
	switch {
	case !ok && isDefault:
		return nil, fmt.Errorf("%w: the rendered file is not readable as a Dependabot file", errSkipManagedFile)
	case !ok:
		return rendered, nil
	}
	root := doc.Content[0]
	merged := false
	if isDefault {
		var err error
		if merged, err = mergeExistingDependabot(dir, fileinfo, root, updates); err != nil {
			return nil, err
		}
	}
	pruned := pruneDependabotRegistries(root, updates)
	if !merged && !pruned {
		return rendered, nil
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// mergeExistingDependabot appends to updates every update entry of the
// existing default Dependabot files that the rendered file does not cover, so
// adopting a repo never removes an ecosystem, directory or target branch it
// already updates. Each ecosystem, target-branch and directory is claimed
// once: the rendered file claims its own and wins there, and an existing entry
// keeps only the directories nobody claimed yet. A directory another existing
// entry already claimed with identical settings is dropped as a duplicate;
// with different settings the merge aborts with
// errConflictingDependabotEntries. A kept entry brings along the registry
// definitions it references (see carryRegistries), and a kept github-actions
// entry stays weekly. The weekly interval is set only after every entry was
// compared, since a narrowed entry shares its schedule node with the settings
// it claimed. It reports whether any entry was appended.
func mergeExistingDependabot(dir string, fileinfo *config.File, root, updates *yaml.Node) (bool, error) {
	// claims maps a directory key to the settings of the existing entry that
	// claimed it, or to nil when the rendered file does.
	claims := map[string]*yaml.Node{}
	for _, entry := range updates.Content {
		eco, dirs, targetBranch := entryKey(entry)
		for _, d := range dirs {
			claims[dependabotDirKey(eco, targetBranch, d)] = nil
		}
	}
	var kept []*yaml.Node
	for _, repoPath := range managedPaths(fileinfo) {
		existing, err := readRegularConfined(dir, repoPath)
		if err != nil {
			return false, err
		}
		if existing == nil {
			continue
		}
		var old yaml.Node
		oldUpdates, ok := dependabotUpdates(existing, &old)
		if !ok {
			return false, fmt.Errorf("%w: %s is not readable as a Dependabot file", errSkipManagedFile, repoPath)
		}
		for _, entry := range oldUpdates.Content {
			keep, err := unclaimedEntry(entry, claims)
			if err != nil {
				return false, err
			}
			if keep == nil {
				continue
			}
			if err := carryRegistries(root, old.Content[0], keep); err != nil {
				return false, err
			}
			kept = append(kept, keep)
		}
	}
	for _, entry := range kept {
		if eco, _, _ := entryKey(entry); eco == "github-actions" {
			setActionsDefaults(entry)
		}
	}
	updates.Content = append(updates.Content, kept...)
	return len(kept) > 0, nil
}

// unclaimedEntry claims entry's directories and returns entry narrowed to the
// ones nobody claimed before, or nil when none are left.
func unclaimedEntry(entry *yaml.Node, claims map[string]*yaml.Node) (*yaml.Node, error) {
	eco, dirs, targetBranch := entryKey(entry)
	settings := entrySettings(entry)
	var rest []string
	for _, d := range dirs {
		key := dependabotDirKey(eco, targetBranch, d)
		owner, claimed := claims[key]
		switch {
		case !claimed:
			claims[key] = settings
			rest = append(rest, d)
		case owner != nil && !sameYAML(owner, settings):
			return nil, fmt.Errorf("%w: two %s entries configure %s differently on %s", errConflictingDependabotEntries, eco, d, branchLabel(targetBranch))
		}
	}
	if len(rest) == 0 {
		return nil, nil
	}
	if len(rest) != len(dirs) {
		setDirectories(entry, rest)
	}
	return entry, nil
}

// dependabotDirKey is one directory an ecosystem updates on a target branch.
func dependabotDirKey(eco, targetBranch, dir string) string {
	return eco + "\x00" + targetBranch + "\x00" + dir
}

// branchLabel names a target-branch in messages.
func branchLabel(targetBranch string) string {
	if targetBranch == "" {
		return "the default branch"
	}
	return "target-branch " + targetBranch
}

// entrySettings is entry without its directory and directories keys.
func entrySettings(entry *yaml.Node) *yaml.Node {
	settings := *entry
	settings.Content = nil
	for i := 0; i+1 < len(entry.Content); i += 2 {
		if key := entry.Content[i].Value; key != "directory" && key != "directories" {
			settings.Content = append(settings.Content, entry.Content[i], entry.Content[i+1])
		}
	}
	return &settings
}

// sameYAML reports whether two nodes hold the same data, ignoring comments,
// quoting, layout and the order of mapping keys.
func sameYAML(a, b *yaml.Node) bool {
	if a.Kind != b.Kind || a.ShortTag() != b.ShortTag() || a.Value != b.Value || len(a.Content) != len(b.Content) {
		return false
	}
	if a.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(a.Content); i += 2 {
			other := mapValue(b, a.Content[i].Value)
			if other == nil || !sameYAML(a.Content[i+1], other) {
				return false
			}
		}
		return true
	}
	for i := range a.Content {
		if !sameYAML(a.Content[i], b.Content[i]) {
			return false
		}
	}
	return true
}

// carryRegistries copies into root each top-level registry definition that
// entry, kept from the existing file oldRoot, references there. A registry
// root already defines differently under the same name aborts the merge with
// errConflictingDependabotEntries.
func carryRegistries(root, oldRoot, entry *yaml.Node) error {
	oldDefs, defs := mapValue(oldRoot, "registries"), mapValue(root, "registries")
	for _, name := range registryRefs(entry, oldDefs) {
		def, current := registryDef(oldDefs, name), registryDef(defs, name)
		switch {
		case def == nil:
			continue
		case current != nil && !sameYAML(current, def):
			return fmt.Errorf("%w: registry %s is defined differently", errConflictingDependabotEntries, name)
		case current == nil:
			if defs == nil || defs.Kind != yaml.MappingNode {
				defs = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
				setMapValue(root, "registries", defs)
			}
			defs.Content = append(defs.Content, scalarNode(name), def)
		}
	}
	return nil
}

// registryDef returns the definition of name in a registries mapping, or nil.
func registryDef(defs *yaml.Node, name string) *yaml.Node {
	if defs == nil || defs.Kind != yaml.MappingNode {
		return nil
	}
	return mapValue(defs, name)
}

// registryRefs returns the registry names entry uses: its registries list, or
// every name defs defines when it uses "*".
func registryRefs(entry, defs *yaml.Node) []string {
	refs := mapValue(entry, "registries")
	if refs == nil {
		return nil
	}
	var names []string
	switch {
	case refs.Kind == yaml.SequenceNode:
		for _, item := range refs.Content {
			names = append(names, item.Value)
		}
	case refs.Value == "*" && defs != nil && defs.Kind == yaml.MappingNode:
		for i := 0; i+1 < len(defs.Content); i += 2 {
			names = append(names, defs.Content[i].Value)
		}
	}
	return names
}

// pruneDependabotRegistries drops top-level registries no update entry
// references, so a repo without pip does not carry the python-index entries.
// It reports whether anything was dropped.
func pruneDependabotRegistries(root, updates *yaml.Node) bool {
	defs := mapValue(root, "registries")
	if defs == nil || defs.Kind != yaml.MappingNode {
		return false
	}
	referenced := map[string]bool{}
	for _, entry := range updates.Content {
		for _, name := range registryRefs(entry, defs) {
			referenced[name] = true
		}
	}
	var kept []*yaml.Node
	for i := 0; i+1 < len(defs.Content); i += 2 {
		if referenced[defs.Content[i].Value] {
			kept = append(kept, defs.Content[i], defs.Content[i+1])
		}
	}
	if len(kept) == len(defs.Content) {
		return false
	}
	if len(kept) == 0 {
		removeMapKey(root, "registries")
	} else {
		defs.Content = kept
	}
	return true
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

// setActionsDefaults keeps a github-actions entry on a weekly interval. Its
// reviewers are left alone: the rendered template sets them and merged entries
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
