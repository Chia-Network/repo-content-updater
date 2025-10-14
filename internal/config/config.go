package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the supported files config
type Config struct {
	Groups    []Group           `yaml:"groups"`
	Files     []File            `yaml:"files"`
	Variables map[string]string `yaml:"variables"`
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

	return config, nil
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
	for _, fileinfo := range c.Files {
		if fileinfo.Name == name {
			return &fileinfo
		}
	}

	return nil
}
