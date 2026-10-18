package repo

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/chia-network/repo-content-updater/internal/config"
)

// Dependabot executes manifest code for bundler, mix, and pip. Listing
// registries on one of those updates disables that execution unless the entry
// sets insecure-external-code-execution to allow. Missing, deny, null, non-string,
// empty, and other ambiguous values are rejected so a broken config cannot pass.
// https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#insecure-external-code-execution
func TestRenderedDependabotRegistriesAllowCodeExecution(t *testing.T) {
	cases := templateRenderCases(t)
	for _, file := range []string{"dependabot.yml", "go-dependabot.yml"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "templates", file))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cases {
			got, err := ProcessTemplate(raw, c.vars, nil)
			if err != nil {
				t.Fatalf("%s %s: %v", file, c.name, err)
			}
			checked, err := validateRegistryCodeExecution(got)
			if err != nil {
				t.Errorf("%s %s: %v", file, c.name, err)
			}
			if file == "dependabot.yml" && checked == 0 {
				t.Errorf("%s %s: no registry-backed manifest ecosystem was checked", file, c.name)
			}
			if file != "dependabot.yml" || checked == 0 {
				continue
			}
			broken := bytes.ReplaceAll(got, []byte("    insecure-external-code-execution: allow\n"), nil)
			if bytes.Equal(broken, got) {
				t.Errorf("%s %s: rendered output has no code-execution allow setting", file, c.name)
				continue
			}
			if _, err := validateRegistryCodeExecution(broken); err == nil {
				t.Errorf("%s %s: removing the allow setting still passed", file, c.name)
			}
		}
	}

	cfg, err := config.LoadConfig(filepath.Join("..", "..", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "..", "templates", "dependabot.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var repoConfig Config
	repoRaw, err := os.ReadFile(filepath.Join("..", "..", ".repo-content-updater.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(repoRaw, &repoConfig); err != nil {
		t.Fatal(err)
	}
	rendered, err := ProcessTemplate(template, cfg.Variables, repoConfig.VarOverrides)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(filepath.Join("..", "..", ".github", "dependabot.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendered, committed) {
		t.Fatalf("rendered dependabot.yml does not match .github/dependabot.yml\n--- rendered ---\n%s\n--- committed ---\n%s", rendered, committed)
	}
	checked, err := validateRegistryCodeExecution(committed)
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("committed dependabot.yml has no registry-backed manifest ecosystem")
	}
}

func TestRegistryCodeExecutionFailClosed(t *testing.T) {
	const allow = "    insecure-external-code-execution: allow\n"
	cases := []struct {
		name    string
		doc     string
		want    string
		checked int
	}{
		{
			name:    "pip list with allow",
			doc:     "updates:\n  - package-ecosystem: pip\n    registries:\n      - chia-pypi\n" + allow,
			checked: 1,
		},
		{
			name: "pip list without allow",
			doc:  "updates:\n  - package-ecosystem: pip\n    registries:\n      - chia-pypi\n",
			want: "lists registries",
		},
		{
			name: "pip deny with registries",
			doc:  "updates:\n  - package-ecosystem: pip\n    registries:\n      - chia-pypi\n    insecure-external-code-execution: deny\n",
			want: "lists registries",
		},
		{
			name: "pip deny without registries",
			doc:  "updates:\n  - package-ecosystem: pip\n    insecure-external-code-execution: deny\n",
		},
		{
			name:    "pip allow without registries",
			doc:     "updates:\n  - package-ecosystem: pip\n" + allow,
			checked: 0,
		},
		{
			name:    "pip star with allow",
			doc:     "updates:\n  - package-ecosystem: pip\n    registries: \"*\"\n" + allow,
			checked: 1,
		},
		{
			name: "pip star without allow",
			doc:  "updates:\n  - package-ecosystem: pip\n    registries: \"*\"\n",
			want: "lists registries",
		},
		{
			name: "bundler star without allow",
			doc:  "updates:\n  - package-ecosystem: bundler\n    registries: \"*\"\n",
			want: "lists registries",
		},
		{
			name:    "mix list with allow",
			doc:     "updates:\n  - package-ecosystem: mix\n    registries:\n      - hex\n" + allow,
			checked: 1,
		},
		{
			name: "npm registries need no allow",
			doc:  "updates:\n  - package-ecosystem: npm\n    registries:\n      - npmjs\n",
		},
		{
			name: "npm cannot set the option",
			doc:  "updates:\n  - package-ecosystem: npm\n    registries:\n      - npmjs\n" + allow,
			want: "does not execute manifest code",
		},
		{
			name: "gomod without registries",
			doc:  "updates:\n  - package-ecosystem: gomod\n",
		},
		{
			name: "missing ecosystem",
			doc:  "updates:\n  - registries:\n      - chia-pypi\n" + allow,
			want: "package-ecosystem",
		},
		{
			name: "empty ecosystem",
			doc:  "updates:\n  - package-ecosystem: \"\"\n    registries:\n      - chia-pypi\n" + allow,
			want: "package-ecosystem",
		},
		{
			name: "padded ecosystem",
			doc:  "updates:\n  - package-ecosystem: \" pip\"\n    registries:\n      - chia-pypi\n" + allow,
			want: "package-ecosystem",
		},
		{
			name: "pip capitalized still needs allow",
			doc:  "updates:\n  - package-ecosystem: Pip\n    registries:\n      - chia-pypi\n",
			want: "lists registries",
		},
		{
			name: "empty registry list",
			doc:  "updates:\n  - package-ecosystem: pip\n    registries: []\n" + allow,
			want: "registries",
		},
		{
			name: "null registries",
			doc:  "updates:\n  - package-ecosystem: pip\n    registries:\n" + allow,
			want: "registries",
		},
		{
			name: "scalar registry name",
			doc:  "updates:\n  - package-ecosystem: pip\n    registries: chia-pypi\n" + allow,
			want: "registries",
		},
		{
			name: "blank registry name",
			doc:  "updates:\n  - package-ecosystem: pip\n    registries:\n      - \"\"\n" + allow,
			want: "registries",
		},
		{
			name: "nested registry name",
			doc:  "updates:\n  - package-ecosystem: pip\n    registries:\n      - [chia-pypi]\n" + allow,
			want: "registries",
		},
		{
			name: "boolean execution",
			doc:  "updates:\n  - package-ecosystem: pip\n    registries:\n      - chia-pypi\n    insecure-external-code-execution: true\n",
			want: "insecure-external-code-execution",
		},
		{
			name: "null execution",
			doc:  "updates:\n  - package-ecosystem: pip\n    registries:\n      - chia-pypi\n    insecure-external-code-execution:\n",
			want: "insecure-external-code-execution",
		},
		{
			name: "padded allow",
			doc:  "updates:\n  - package-ecosystem: pip\n    registries:\n      - chia-pypi\n    insecure-external-code-execution: \"allow \"\n",
			want: "insecure-external-code-execution",
		},
		{
			name: "wrong allow case",
			doc:  "updates:\n  - package-ecosystem: pip\n    registries:\n      - chia-pypi\n    insecure-external-code-execution: ALLOW\n",
			want: "insecure-external-code-execution",
		},
		{
			name: "duplicate ecosystem",
			doc:  "updates:\n  - package-ecosystem: pip\n    package-ecosystem: bundler\n    registries:\n      - chia-pypi\n" + allow,
			want: "duplicate",
		},
		{
			name: "merge key",
			doc:  "updates:\n  - package-ecosystem: pip\n    <<: {registries: [chia-pypi]}\n",
			want: "merge key",
		},
		{
			name: "empty updates",
			doc:  "updates: []\n",
		},
		{
			name: "updates not a list",
			doc:  "updates: 1\n",
			want: "dependabot config",
		},
		{
			name: "broken yaml",
			doc:  "updates: [\n",
			want: "dependabot config",
		},
		{
			name: "empty document",
			doc:  "",
			want: "dependabot config",
		},
		{
			name: "second document",
			doc:  "updates:\n  - package-ecosystem: pip\n" + allow + "---\nupdates: []\n",
			want: "more than one document",
		},
		{
			name: "later bundler entry still fails",
			doc: "updates:\n  - package-ecosystem: pip\n    registries:\n      - chia-pypi\n" + allow +
				"  - package-ecosystem: bundler\n    registries:\n      - ruby\n",
			want: "lists registries",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checked, err := validateRegistryCodeExecution([]byte(c.doc))
			if c.want == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if checked != c.checked {
					t.Fatalf("checked = %d, want %d", checked, c.checked)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want substring %q", err, c.want)
			}
		})
	}
}

type dependabotUpdate struct {
	ecosystem   string
	registries  bool
	codeExec    string
	codeExecSet bool
}

func (u *dependabotUpdate) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode || len(node.Content)%2 != 0 {
		return errors.New("update entry is not a mapping")
	}
	seen := map[string]struct{}{}
	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		if keyNode.Kind == yaml.ScalarNode && (keyNode.Tag == "!!merge" || keyNode.Value == "<<") {
			return errors.New("update entry uses a merge key")
		}
		key, err := plainString(keyNode)
		if err != nil {
			return fmt.Errorf("update key: %w", err)
		}
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate update key %q", key)
		}
		seen[key] = struct{}{}
		val := node.Content[i+1]
		switch key {
		case "package-ecosystem":
			u.ecosystem, err = plainString(val)
			if err != nil {
				return fmt.Errorf("package-ecosystem: %w", err)
			}
		case "registries":
			if err = decodeRegistries(val); err != nil {
				return fmt.Errorf("registries: %w", err)
			}
			u.registries = true
		case "insecure-external-code-execution":
			u.codeExec, err = decodeCodeExecution(val)
			if err != nil {
				return fmt.Errorf("insecure-external-code-execution: %w", err)
			}
			u.codeExecSet = true
		}
	}
	if _, ok := seen["package-ecosystem"]; !ok {
		return errors.New("update is missing package-ecosystem")
	}
	return nil
}

func validateRegistryCodeExecution(raw []byte) (int, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc struct {
		Updates []dependabotUpdate `yaml:"updates"`
	}
	if err := dec.Decode(&doc); err != nil {
		return 0, fmt.Errorf("dependabot config: %w", err)
	}
	var extra yaml.Node
	err := dec.Decode(&extra)
	if err == nil {
		return 0, errors.New("dependabot config has more than one document")
	}
	if !errors.Is(err, io.EOF) {
		return 0, fmt.Errorf("dependabot config: %w", err)
	}
	checked := 0
	for i, update := range doc.Updates {
		needsCode := executesManifestCode(update.ecosystem)
		if update.codeExecSet && !needsCode {
			return 0, fmt.Errorf("update %d (%s) does not execute manifest code", i, update.ecosystem)
		}
		if !needsCode || !update.registries {
			continue
		}
		checked++
		if update.codeExec != "allow" {
			return 0, fmt.Errorf("update %d (%s) lists registries but insecure-external-code-execution is %q", i, update.ecosystem, update.codeExec)
		}
	}
	return checked, nil
}

func executesManifestCode(ecosystem string) bool {
	switch strings.ToLower(ecosystem) {
	case "bundler", "mix", "pip":
		return true
	default:
		return false
	}
}

func decodeRegistries(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		name, err := plainString(node)
		if err != nil || name != "*" {
			return errors.New("must be a list of names or \"*\"")
		}
		return nil
	case yaml.SequenceNode:
		if len(node.Content) == 0 {
			return errors.New("list is empty")
		}
		for _, item := range node.Content {
			if _, err := plainString(item); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("must be a list of names or \"*\"")
	}
}

func decodeCodeExecution(node *yaml.Node) (string, error) {
	value, err := plainString(node)
	if err != nil {
		return "", err
	}
	if value != "allow" && value != "deny" {
		return "", errors.New("must be allow")
	}
	return value, nil
}

func plainString(node *yaml.Node) (string, error) {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return "", errors.New("must be a string")
	}
	if node.Value == "" || strings.TrimSpace(node.Value) != node.Value {
		return "", errors.New("must be an unambiguous string")
	}
	return node.Value, nil
}
