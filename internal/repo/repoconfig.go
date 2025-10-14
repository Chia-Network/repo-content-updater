package repo

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds configuration data for a repository, including information
// about target branches, users to assign, groups, and commit prefixes.
type Config struct {
	PrTargetBranch *string           `yaml:"pr_target_branch"`
	AssignUsers    []string          `yaml:"assign_users"`
	AssignGroup    *string           `yaml:"assign_group"`
	CommitPrefix   *string           `yaml:"commit_prefix"`
	VarOverrides   map[string]interface{} `yaml:"var_overrides"`
}

// LoadRepoConfig loads the repository configuration from the .repo-content-updater.yml file.
// It returns a RepoConfig struct filled with the loaded configuration and any error encountered during loading.
func (c *Content) LoadRepoConfig(repopath string) (Config, error) {
	// Support yml and yaml variants
	path := filepath.Join(repopath, ".repo-content-updater.yaml")
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		path = filepath.Join(repopath, ".repo-content-updater.yml")
	}

	configBytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, nil
		}
		return Config{}, err
	}

	var repoconfig Config
	err = yaml.Unmarshal(configBytes, &repoconfig)
	if err != nil {
		return Config{}, err
	}

	return repoconfig, nil

}
