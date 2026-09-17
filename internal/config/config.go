package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the supported files config
type Config struct {
	Groups    []Group           `yaml:"groups"`
	Files     []File            `yaml:"files"`
	Variables map[string]string `yaml:"variables"`

	managedFileLookup map[string]string
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

	return config, nil
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

	pathOwners := map[string]map[string]struct{}{}
	for i := range c.Files {
		file := &c.Files[i]
		c.registerManagedFileLookup(file.Name, file.Name)
		for _, alias := range file.Aliases {
			c.registerManagedFileLookup(alias, file.Name)
		}

		paths := append([]string{file.RepoPath}, file.AlternatePaths...)
		for _, path := range paths {
			key := normalizeManagedFileKey(path)
			if key == "" {
				continue
			}
			if pathOwners[key] == nil {
				pathOwners[key] = map[string]struct{}{}
			}
			pathOwners[key][file.Name] = struct{}{}
		}
	}

	for path, owners := range pathOwners {
		if len(owners) != 1 {
			continue
		}
		for name := range owners {
			c.registerManagedFileLookup(path, name)
			break
		}
	}
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
