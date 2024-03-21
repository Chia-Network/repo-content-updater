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
}
