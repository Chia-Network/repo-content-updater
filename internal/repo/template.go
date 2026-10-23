package repo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"
)

// ProcessTemplate renders the given template file.
//
// Plain Go actions still render as before. Two whole-line spellings keep a
// template valid YAML before rendering, and they render to the same bytes:
//
//	key: "{{ .Name }}"     the entire value is one quoted field
//	# {{- if ... }}        the entire line is a comment-wrapped action
func ProcessTemplate(templateContent []byte, defaultVars map[string]string, overrides map[string]string) ([]byte, error) {
	return processTemplate(templateContent, mergeTemplateVars(defaultVars, overrides))
}

// ProcessNamedTemplate renders the template file templateName like
// ProcessTemplate, with the variables the managed-file run gives that
// template (see templateVarsFor).
func ProcessNamedTemplate(templateName string, templateContent []byte, defaultVars map[string]string, overrides map[string]string) ([]byte, error) {
	return processTemplate(templateContent, templateVarsFor(templateName, defaultVars, overrides))
}

// CURRENT_YEAR is fixed in every merge, and Dependabot flags and the adoption
// marker are computed rather than configured, so none may be replaced by an
// override.
var notOverridableTemplateVars = func() map[string]bool {
	vars := map[string]bool{"CURRENT_YEAR": true, adoptionMarkerVar: true}
	for _, ecosystem := range dependabotEcosystems {
		vars[ecosystem.enabledVar] = true
	}
	return vars
}()

func mergeTemplateVars(defaultVars map[string]string, overrides map[string]string) map[string]string {
	data := map[string]string{
		"CURRENT_YEAR": strconv.Itoa(time.Now().Year()),
	}

	// Merge `defaultVars` into `data`
	for key, value := range defaultVars {
		if key == "CURRENT_YEAR" {
			continue
		}
		data[key] = value
	}

	// Merge `overrides` into `data`, with `overrides` taking precedence
	for key, value := range overrides {
		if notOverridableTemplateVars[key] {
			continue
		}
		data[key] = value
	}

	return data
}

func processTemplate(templateContent []byte, data map[string]string) ([]byte, error) {
	// Compute the SHA256 hash of the template content
	hash := sha256.Sum256(templateContent)
	hexHash := hex.EncodeToString(hash[:])

	tmpl, err := template.New(hexHash).Parse(expandYAMLSafeActions(string(templateContent)))
	if err != nil {
		return nil, err
	}

	var processedTemplate bytes.Buffer
	if err = tmpl.Execute(&processedTemplate, data); err != nil {
		return nil, err
	}

	return processedTemplate.Bytes(), nil
}

// A YAML key whose whole value is one quoted field, or a comment line whose
// whole body is one trim-marked control action. Nothing else is rewritten.
var (
	yamlQuotedField   = regexp.MustCompile(`^([ \t]*)([A-Za-z0-9_-]+)(:[ \t]*)"\{\{ \.([A-Za-z_][A-Za-z0-9_]*) \}\}"$`)
	yamlCommentAction = regexp.MustCompile(`^([ \t]*)#([ \t]*)(\{\{- (?:if|else|end|range|with)(?: [^}]*)?\}\})$`)
)

// expandYAMLSafeActions lowers those two line spellings to plain Go actions.
func expandYAMLSafeActions(src string) string {
	if !strings.Contains(src, "{{") {
		return src
	}
	lines := strings.Split(src, "\n")
	changed := false
	for i, line := range lines {
		rewritten, ok := yamlSafeActionLine(line)
		if !ok {
			continue
		}
		lines[i] = rewritten
		changed = true
	}
	if !changed {
		return src
	}
	return strings.Join(lines, "\n")
}

func yamlSafeActionLine(line string) (string, bool) {
	if m := yamlQuotedField.FindStringSubmatch(line); m != nil {
		return m[1] + m[2] + m[3] + "{{ ." + m[4] + " }}", true
	}
	if m := yamlCommentAction.FindStringSubmatch(line); m != nil {
		return m[3], true
	}
	return "", false
}
