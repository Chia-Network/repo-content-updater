package config

import (
	"fmt"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the supported files config
type Config struct {
	Groups       []Group           `yaml:"groups"`
	Files        []File            `yaml:"files"`
	DefaultFiles []string          `yaml:"default_files"` // canonical roots; companions expand per repo
	Variables    map[string]string `yaml:"variables"`

	managedFileLookup map[string]string
	managedPathOwners map[string]map[string]struct{}
}

// FileOrigin records why a managed file was selected for a repo.
type FileOrigin int

const (
	// OriginExplicit means the file was named by the repo's managed-files property.
	OriginExplicit FileOrigin = iota
	// OriginDefault means the file comes only from config default_files.
	OriginDefault
)

// SelectedFile is a canonical managed file name plus its selection origin.
type SelectedFile struct {
	Name   string
	Origin FileOrigin
}

// ManagedFileSelection is the resolved managed-files set for one repo.
type ManagedFileSelection struct {
	Explicit []string
	Defaults []string
}

// Group is a defined group of template files to include at once
type Group struct {
	Name      string   `yaml:"name"`
	Templates []string `yaml:"templates"`
}

// File a single supported file within the files list
type File struct {
	Name           string   `yaml:"name"`
	TemplateName   string   `yaml:"template_name"`
	RepoPath       string   `yaml:"repo_path"`
	AlternatePaths []string `yaml:"alternate_paths"`
	Aliases        []string `yaml:"aliases"`
	CompanionFiles []string `yaml:"companion_files"`
}

// LoadConfig loads config from the given path
func LoadConfig(path string) (*Config, error) {
	configBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := &Config{}

	err = yaml.Unmarshal(configBytes, config)
	if err != nil {
		return nil, err
	}

	config.buildManagedFileLookup()

	if err := config.resolveDefaultFiles(); err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) resolveDefaultFiles() error {
	if len(c.DefaultFiles) == 0 {
		return nil
	}

	roots := make([]string, 0, len(c.DefaultFiles))
	seen := map[string]bool{}
	for _, entry := range c.DefaultFiles {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return fmt.Errorf("default_files contains an empty entry")
		}
		if strings.HasPrefix(entry, "!") || strings.HasPrefix(entry, "group:") {
			return fmt.Errorf("default_files entry %q must name a file or alias", entry)
		}
		name, ok := c.ResolveManagedFileName(entry)
		if !ok || strings.HasPrefix(name, "group:") {
			return fmt.Errorf("default_files entry %q does not resolve to a known file", entry)
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		roots = append(roots, name)
	}

	expanded, err := c.EnsureCompanionFiles(roots)
	if err != nil {
		return fmt.Errorf("default_files: %w", err)
	}

	claimed := map[string]bool{}
	for _, name := range expanded {
		if c.sharesRepoPathWith(name, claimed) {
			return fmt.Errorf("default_files entry %q writes the same repo path as another default file", name)
		}
		claimed[name] = true
	}

	c.DefaultFiles = roots
	return nil
}

func normalizeManagedFileKey(key string) string {
	key = strings.TrimSpace(key)
	key = strings.TrimPrefix(key, "./")
	return strings.ToLower(key)
}

func (c *Config) registerManagedFileLookup(key, canonicalName string) {
	key = normalizeManagedFileKey(key)
	if key == "" {
		return
	}
	c.managedFileLookup[key] = canonicalName
}

func (c *Config) buildManagedFileLookup() {
	c.managedFileLookup = map[string]string{}
	c.managedPathOwners = map[string]map[string]struct{}{}

	for i := range c.Files {
		file := &c.Files[i]
		c.registerManagedFileLookup(file.Name, file.Name)
		for _, alias := range file.Aliases {
			c.registerManagedFileLookup(alias, file.Name)
		}

		for _, path := range c.repoPathKeys(file) {
			if c.managedPathOwners[path] == nil {
				c.managedPathOwners[path] = map[string]struct{}{}
			}
			c.managedPathOwners[path][file.Name] = struct{}{}
		}
	}

	for path, owners := range c.managedPathOwners {
		if len(owners) != 1 {
			continue
		}
		for name := range owners {
			c.registerManagedFileLookup(path, name)
			break
		}
	}
}

func (c *Config) repoPathKeys(file *File) []string {
	keys := make([]string, 0, 1+len(file.AlternatePaths))
	add := func(filePath string) {
		key := normalizeManagedFileKey(filePath)
		if key != "" {
			keys = append(keys, key)
		}
	}
	add(file.RepoPath)
	for _, alternate := range file.AlternatePaths {
		add(alternate)
	}
	return keys
}

func (c *Config) sharesRepoPathWith(fileName string, names map[string]bool) bool {
	file := c.GetFileInfo(fileName)
	if file == nil {
		return false
	}
	for _, key := range c.repoPathKeys(file) {
		for owner := range c.managedPathOwners[key] {
			if owner != fileName && names[owner] {
				return true
			}
		}
	}
	return false
}

// ResolveManagedFileName maps a managed-files property entry to a canonical file name.
func (c *Config) ResolveManagedFileName(entry string) (string, bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" || strings.HasPrefix(entry, "group:") {
		return entry, entry != ""
	}
	if canonical, ok := c.managedFileLookup[normalizeManagedFileKey(entry)]; ok {
		return canonical, true
	}
	if c.GetFileInfo(entry) != nil {
		return entry, true
	}
	return "", false
}

// ResolveManagedFileSelection turns a repo's raw managed-files entries into
// explicit files and default files. `!name` removes a file from both sets,
// unless another selected file requires it as a companion.
// Unknown entries are logged and ignored.
func (c *Config) ResolveManagedFileSelection(repoName string, entries []string) ManagedFileSelection {
	optOuts := map[string]bool{}
	var selectionEntries []string

	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.HasPrefix(raw, "!") {
			name, ok := c.ResolveManagedFileName(strings.TrimSpace(strings.TrimPrefix(raw, "!")))
			if !ok || strings.HasPrefix(name, "group:") {
				log.Printf("Unknown managed-files entry %q for %s; ignoring\n", raw, repoName)
				continue
			}
			optOuts[name] = true
			continue
		}
		selectionEntries = append(selectionEntries, raw)
	}

	explicit := c.resolveSelectedFiles(repoName, c.expandSelectionRoots(repoName, selectionEntries), optOuts)

	explicitSet := map[string]bool{}
	for _, name := range explicit {
		explicitSet[name] = true
	}

	defaults := c.resolveSelectedFiles(repoName, c.DefaultFiles, optOuts)

	selectedDefaults := make([]string, 0, len(defaults))
	for _, name := range defaults {
		if explicitSet[name] || c.sharesRepoPathWith(name, explicitSet) || c.sharesRepoPathWith(name, optOuts) {
			continue
		}
		selectedDefaults = append(selectedDefaults, name)
	}

	return ManagedFileSelection{Explicit: explicit, Defaults: selectedDefaults}
}

func (c *Config) resolveSelectedFiles(repoName string, roots []string, optOuts map[string]bool) []string {
	filtered := filterOptOuts(roots, optOuts)
	files, err := c.EnsureCompanionFiles(filtered)
	if err != nil {
		log.Printf("Error ensuring companion files for %s: %s\n", repoName, err)
		return nil
	}
	logRequiredCompanionOptOuts(repoName, files, optOuts)
	return files
}

func (c *Config) expandSelectionRoots(repoName string, entries []string) []string {
	var roots []string
	seen := map[string]bool{}
	for _, raw := range entries {
		expanded, _ := c.expandManagedFileEntries([]string{raw}, false)
		if len(expanded) == 0 {
			log.Printf("Unknown managed-files entry %q for %s; ignoring\n", raw, repoName)
			continue
		}
		for _, name := range expanded {
			if seen[name] {
				continue
			}
			seen[name] = true
			roots = append(roots, name)
		}
	}
	return roots
}

func filterOptOuts(files []string, optOuts map[string]bool) []string {
	filtered := make([]string, 0, len(files))
	for _, name := range files {
		if !optOuts[name] {
			filtered = append(filtered, name)
		}
	}
	return filtered
}

func logRequiredCompanionOptOuts(repoName string, files []string, optOuts map[string]bool) {
	for _, name := range files {
		if !optOuts[name] {
			continue
		}
		log.Printf(
			"Ignoring opt-out of %q for %s: it is required as a companion by another selected file\n",
			name,
			repoName,
		)
	}
}

// ExpandGroup takes a group name and returns the files the group corresponds to
func (c *Config) ExpandGroup(name string) ([]string, error) {
	for _, group := range c.Groups {
		if group.Name == name {
			return group.Templates, nil
		}
	}

	return nil, fmt.Errorf("unknown group: %s", name)
}

// GetFileInfo returns settings for a single file
func (c *Config) GetFileInfo(name string) *File {
	for i := range c.Files {
		if c.Files[i].Name == name {
			return &c.Files[i]
		}
	}

	return nil
}

// EnsureCompanionFiles appends companion_files for any listed template so workflow
// and script templates stay paired even when callers pass a flat file list.
func (c *Config) EnsureCompanionFiles(files []string) ([]string, error) {
	seen := map[string]bool{}
	var finalized []string

	var addName func(string) error
	addName = func(name string) error {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return nil
		}
		fileinfo := c.GetFileInfo(name)
		if fileinfo == nil {
			return nil
		}
		seen[name] = true
		finalized = append(finalized, name)
		for _, companion := range fileinfo.CompanionFiles {
			if c.GetFileInfo(companion) == nil {
				return fmt.Errorf("unknown companion file %q for %q", companion, name)
			}
			if err := addName(companion); err != nil {
				return err
			}
		}
		return nil
	}

	for _, file := range files {
		canonical, ok := c.ResolveManagedFileName(file)
		if !ok {
			continue
		}
		if strings.HasPrefix(canonical, "group:") {
			continue
		}
		if err := addName(canonical); err != nil {
			return nil, err
		}
	}

	return finalized, nil
}

// ExpandManagedFileEntries expands group: references and companion_files into a
// deduplicated file name list (stable order: first mention wins placement, companions append).
func (c *Config) ExpandManagedFileEntries(entries []string) ([]string, error) {
	return c.expandManagedFileEntries(entries, true)
}

func (c *Config) expandManagedFileEntries(entries []string, includeCompanions bool) ([]string, error) {
	var expanded []string
	seen := map[string]bool{}

	var addName func(string) error
	addName = func(name string) error {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return nil
		}
		if strings.HasPrefix(name, "group:") {
			group := name[len("group:"):]
			groupFiles, err := c.ExpandGroup(group)
			if err != nil {
				return nil
			}
			for _, gf := range groupFiles {
				if err := addName(gf); err != nil {
					return err
				}
			}
			return nil
		}
		canonical, ok := c.ResolveManagedFileName(name)
		if !ok {
			return nil
		}
		name = canonical
		if seen[name] {
			return nil
		}
		fileinfo := c.GetFileInfo(name)
		if fileinfo == nil {
			return nil
		}
		seen[name] = true
		expanded = append(expanded, name)
		if !includeCompanions {
			return nil
		}
		for _, companion := range fileinfo.CompanionFiles {
			if c.GetFileInfo(companion) == nil {
				return fmt.Errorf("unknown companion file %q for %q", companion, name)
			}
			if err := addName(companion); err != nil {
				return err
			}
		}
		return nil
	}

	for _, entry := range entries {
		if err := addName(entry); err != nil {
			return nil, err
		}
	}
	return expanded, nil
}
