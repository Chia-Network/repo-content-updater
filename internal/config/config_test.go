package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chia-network/repo-content-updater/internal/config"
)

func TestConfigIsValid(t *testing.T) {
	cfg, err := config.LoadConfig("../../config.yaml")
	assert.Nil(t, err)

	for _, group := range cfg.Groups {
		files, err := cfg.ExpandGroup(group.Name)
		assert.Nil(t, err)
		assert.Equal(t, len(group.Templates), len(files))
	}

	expanded, err := cfg.ExpandManagedFileEntries([]string{"dependency-cursor-review"})
	assert.Nil(t, err)
	assert.Equal(t, []string{"dependency-cursor-review", "malware-verdict-formatter"}, expanded)

	groupExpanded, err := cfg.ExpandManagedFileEntries([]string{"group:dependency-cursor-review"})
	assert.Nil(t, err)
	assert.Equal(t, []string{"dependency-cursor-review", "malware-verdict-formatter"}, groupExpanded)
}
