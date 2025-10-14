package repo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"text/template"
	"time"
)

// ProcessTemplate renders the given template file
func ProcessTemplate(templateContent []byte, defaultVars map[string]interface{}, overrides map[string]interface{}) ([]byte, error) {
	// Compute the SHA256 hash of the template content
	hash := sha256.Sum256(templateContent)
	hexHash := hex.EncodeToString(hash[:])

	notOverridable := map[string]bool{"CURRENT_YEAR": true}
	data := map[string]interface{}{
		"CURRENT_YEAR": strconv.Itoa(time.Now().Year()),
	}

	// Merge `defaultVars` into `data`
	for key, value := range defaultVars {
		if notOverridable[key] {
			continue
		}
		data[key] = value
	}

	// Merge `overrides` into `data`, with `overrides` taking precedence
	for key, value := range overrides {
		if notOverridable[key] {
			continue
		}
		data[key] = value
	}

	tmpl, err := template.New(hexHash).Parse(string(templateContent))
	if err != nil {
		return nil, err
	}

	var processedTemplate bytes.Buffer
	if err = tmpl.Execute(&processedTemplate, data); err != nil {
		return nil, err
	}

	return processedTemplate.Bytes(), nil
}
