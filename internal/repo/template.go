package repo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"text/template"
	"time"
)

// ProcessTemplate renders the given template file.
//
// Plain Go actions still render as before. Two extra spellings keep a
// template valid YAML before rendering, and they render to the same bytes:
//
//	"{{ .Name }}"    a quoted action, rendered without the quotes
//	# {{- if ... }}  a comment whose body is one action, rendered as that action
func ProcessTemplate(templateContent []byte, defaultVars map[string]string, overrides map[string]string) ([]byte, error) {
	// Compute the SHA256 hash of the template content
	hash := sha256.Sum256(templateContent)
	hexHash := hex.EncodeToString(hash[:])

	notOverridable := map[string]bool{"CURRENT_YEAR": true}
	data := map[string]string{
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

// expandYAMLSafeActions lowers YAML-legal template spellings to plain Go actions.
func expandYAMLSafeActions(src string) string {
	return expandCommentTemplateActions(expandQuotedTemplateActions(src))
}

func expandQuotedTemplateActions(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	for i := 0; i < len(src); {
		action, next, ok := quotedActionAt(src, i)
		if !ok {
			b.WriteByte(src[i])
			i++
			continue
		}
		b.WriteString(action)
		i = next
	}
	return b.String()
}

func quotedActionAt(src string, i int) (string, int, bool) {
	if i >= len(src) || src[i] != '"' {
		return "", 0, false
	}
	rest := src[i+1:]
	if !strings.HasPrefix(rest, "{{") {
		return "", 0, false
	}
	rel := strings.Index(rest, "}}\"")
	if rel < 0 {
		return "", 0, false
	}
	action := rest[:rel+2]
	if !singleTemplateAction(action) {
		return "", 0, false
	}
	return action, i + 1 + rel + 3, true
}

func expandCommentTemplateActions(src string) string {
	if !strings.Contains(src, "#") {
		return src
	}
	lines := strings.Split(src, "\n")
	changed := false
	for i, line := range lines {
		action, ok := commentTemplateAction(line)
		if !ok {
			continue
		}
		lines[i] = action
		changed = true
	}
	if !changed {
		return src
	}
	return strings.Join(lines, "\n")
}

func commentTemplateAction(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "#") {
		return "", false
	}
	body := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
	if !singleTemplateAction(body) {
		return "", false
	}
	return body, true
}

func singleTemplateAction(s string) bool {
	if len(s) < 4 || !strings.HasPrefix(s, "{{") || !strings.HasSuffix(s, "}}") {
		return false
	}
	inner := s[2 : len(s)-2]
	return !strings.Contains(inner, "{{") && !strings.Contains(inner, "}}")
}
