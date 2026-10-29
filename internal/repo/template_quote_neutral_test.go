package repo

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/chia-network/repo-content-updater/internal/config"
)

// TestAlwaysOnWorkflowTemplatesAreQuoteNeutral keeps managed workflow templates
// free of quoted scalar values so prettier configs with singleQuote: true do
// not rewrite them.
func TestAlwaysOnWorkflowTemplatesAreQuoteNeutral(t *testing.T) {
	root := filepath.Join("..", "..")
	cfg, err := config.LoadConfig(filepath.Join(root, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"dependency-review.yml",
		"check-commit-signing.yml",
		"check-node-runtime.yml",
		"go-test.yml",
	} {
		raw, err := os.ReadFile(filepath.Join(root, "templates", name))
		if err != nil {
			t.Fatal(err)
		}
		rendered, err := ProcessTemplate(raw, cfg.Variables, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(rendered, &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		assertQuoteNeutralScalars(t, name, &doc, false)
	}
}

func assertQuoteNeutralScalars(t *testing.T, name string, node *yaml.Node, isKey bool) {
	t.Helper()
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			assertQuoteNeutralScalars(t, name, child, false)
		}
	case yaml.MappingNode:
		for i, child := range node.Content {
			assertQuoteNeutralScalars(t, name, child, i%2 == 0)
		}
	case yaml.ScalarNode:
		if !isKey && (node.Style&yaml.DoubleQuotedStyle != 0 || node.Style&yaml.SingleQuotedStyle != 0) {
			t.Errorf("%s: quoted scalar %q at line %d", name, node.Value, node.Line)
		}
	}
}

// TestNoNodeOlderThan24 keeps workflows and templates on Node 24 or newer and
// catches the node20 dependabot/fetch-metadata pin.
func TestNoNodeOlderThan24(t *testing.T) {
	root := filepath.Join("..", "..")
	cfg, err := config.LoadConfig(filepath.Join(root, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dirs := []struct {
		path   string
		render bool
	}{
		{path: filepath.Join(root, ".github", "workflows")},
		{path: filepath.Join(root, "templates"), render: true},
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir.path)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !isYAMLName(entry.Name()) {
				continue
			}
			name := filepath.Join(dir.path, entry.Name())
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if dir.render {
				raw, err = ProcessTemplate(raw, cfg.Variables, nil)
				if err != nil {
					t.Fatalf("%s: render failed: %v", name, err)
				}
			}
			var doc yaml.Node
			if err := yaml.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("%s: does not parse as YAML after rendering: %v", name, err)
			}
			assertNodeVersionsAtLeast24(t, name, &doc)
		}
	}

	artifactReview, err := os.ReadFile(filepath.Join(root, "templates", artifactReviewTemplate))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(artifactReview), "21025c705c08248db411dc16f3619e6b5f9ea21a") {
		t.Errorf("%s still pins the node20 dependabot/fetch-metadata commit", artifactReviewTemplate)
	}
}

func assertNodeVersionsAtLeast24(t *testing.T, name string, doc *yaml.Node) {
	t.Helper()
	jobs := mappingValue(documentRoot(doc), "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return
	}
	for i := 1; i < len(jobs.Content); i += 2 {
		steps := mappingValue(jobs.Content[i], "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		for _, step := range steps.Content {
			uses := mappingValue(step, "uses")
			if uses == nil || uses.Kind != yaml.ScalarNode ||
				!strings.HasPrefix(uses.Value, "actions/setup-node@") {
				continue
			}
			with := mappingValue(step, "with")
			version := mappingValue(with, "node-version")
			if version == nil || version.Kind != yaml.ScalarNode {
				t.Errorf("%s: %s has no node-version", name, uses.Value)
				continue
			}
			number, err := strconv.Atoi(version.Value)
			if err != nil || number < 24 {
				t.Errorf("%s: %s uses node-version %q, want an integer >= 24", name, uses.Value, version.Value)
			}
		}
	}
}

func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0]
	}
	return doc
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Kind == yaml.ScalarNode && node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
