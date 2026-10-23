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

	result, err := repo.ProcessTemplate(template, map[string]string{"CGO_ENABLED": "0"}, map[string]string{})
	assert.Nil(t, err)
	assert.Equal(t, string([]byte(fmt.Sprintf("%d 0", time.Now().Year()))), string(result))

	// Ensure allowed overrides work
	result, err = repo.ProcessTemplate(template, map[string]string{}, map[string]string{"CGO_ENABLED": "1"})
	assert.Nil(t, err)
	assert.Equal(t, []byte(fmt.Sprintf("%d 1", time.Now().Year())), result)

	// Ensure disallowed overrides dont override
	result, err = repo.ProcessTemplate(template, map[string]string{}, map[string]string{
		"CGO_ENABLED":  "1",
		"CURRENT_YEAR": "1990",
	})
	assert.Nil(t, err)
	assert.Equal(t, []byte(fmt.Sprintf("%d 1", time.Now().Year())), result)
}

// TestProcessTemplateLeavesDirectoryPinsAsWritten keeps Dependabot directory
// handling out of the generic template merge: only the Dependabot template
// turns a bare pin into a directories list.
func TestProcessTemplateLeavesDirectoryPinsAsWritten(t *testing.T) {
	template := []byte(`{{ .DEPENDABOT_GOMOD_DIRECTORY }}`)
	pin := map[string]string{"DEPENDABOT_GOMOD_DIRECTORY": "/svc"}
	result, err := repo.ProcessTemplate(template, pin, nil)
	assert.Nil(t, err)
	assert.Equal(t, "/svc", string(result))

	result, err = repo.ProcessNamedTemplate("other.yml", template, nil, pin)
	assert.Nil(t, err)
	assert.Equal(t, "/svc", string(result))

	result, err = repo.ProcessNamedTemplate("dependabot.yml", template, nil, pin)
	assert.Nil(t, err)
	assert.Equal(t, `["/svc"]`, string(result))
}
