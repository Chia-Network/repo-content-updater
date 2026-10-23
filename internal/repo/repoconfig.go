package repo

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds configuration data for a repository, including information
// about target branches, users to assign, groups, and commit prefixes.
type Config struct {
	PrTargetBranch *string           `yaml:"pr_target_branch"`
	AssignUsers    []string          `yaml:"assign_users"`
	AssignGroup    *string           `yaml:"assign_group"`
	CommitPrefix   *string           `yaml:"commit_prefix"`
	VarOverrides   map[string]string `yaml:"var_overrides"`
}

// LoadRepoConfig loads the repository configuration from the .repo-content-updater.yml file.
// It returns a RepoConfig struct filled with the loaded configuration and any error encountered during loading.
func (c *Content) LoadRepoConfig(repopath string) (Config, error) {
	// Support yml and yaml variants. Only a regular file inside the checkout
	// is read; anything else is treated as no repo config.
	var configBytes []byte
	for _, name := range []string{".repo-content-updater.yaml", ".repo-content-updater.yml"} {
		target, info, err := lstatConfined(repopath, name)
		if err != nil {
			return Config{}, err
		}
		if info == nil {
			continue
		}
		if !info.Mode().IsRegular() {
			log.Printf("Ignoring %s in %s: not a regular file\n", name, repopath)
			continue
		}
		if configBytes, err = os.ReadFile(target); err != nil {
			return Config{}, err
		}
		break
	}
	if configBytes == nil {
		return Config{}, nil
	}

	var repoconfig Config
	err := yaml.Unmarshal(configBytes, &repoconfig)
	if err != nil {
		return Config{}, err
	}

	return repoconfig, nil

}
