package repo_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/chia-network/repo-content-updater/internal/repo"
)

func TestProcessTemplateOverrides(t *testing.T) {
	template := []byte(`{{ .CURRENT_YEAR }} {{ .CGO_ENABLED }}`)

	result, err := repo.ProcessTemplate(template, map[string]string{})
	assert.Nil(t, err)
	assert.Equal(t, []byte(fmt.Sprintf("%d 0", time.Now().Year())), result)

	// Ensure allowed overrides work
	result, err = repo.ProcessTemplate(template, map[string]string{"CGO_ENABLED": "1"})
	assert.Nil(t, err)
	assert.Equal(t, []byte(fmt.Sprintf("%d 1", time.Now().Year())), result)

	// Ensure disallowed overrides dont override
	result, err = repo.ProcessTemplate(template, map[string]string{
		"CGO_ENABLED":  "1",
		"CURRENT_YEAR": "1990",
	})
	assert.Nil(t, err)
	assert.Equal(t, []byte(fmt.Sprintf("%d 1", time.Now().Year())), result)
}
