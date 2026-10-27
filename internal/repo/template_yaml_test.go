package repo

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/chia-network/repo-content-updater/internal/config"
)

func TestParsedUsesMatchActionLines(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !isYAMLName(name) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("..", "..", "templates", name))
		if err != nil {
			t.Fatal(err)
		}
		parsed := map[string]int{}
		for _, uses := range usesValues(t, raw) {
			parsed[uses]++
		}
		for _, uses := range actionUsesLines(string(raw)) {
			if parsed[uses] == 0 {
				t.Errorf("%s: parsed YAML is missing %s", name, uses)
				continue
			}
			parsed[uses]--
		}
	}
}

func TestYAMLTemplatesParse(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	sawYAML := false
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !isYAMLName(name) {
			continue
		}
		sawYAML = true
		raw, err := os.ReadFile(filepath.Join("..", "..", "templates", name))
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Errorf("%s does not parse as YAML: %v", name, err)
		}
	}
	if !sawYAML {
		t.Fatal("no YAML templates found")
	}
}

func TestExpandYAMLSafeActions(t *testing.T) {
	src := "" +
		"key: \"{{ .Name }}\"\n" +
		"# {{- if eq .On \"1\" }}\n" +
		"nested: \"{{ .Raw }}\"\n" +
		"# {{- end }}\n" +
		"expr: ${{`{{ github.token }}`}}\n"
	prose := "# see the {{ .Name }} field later\n"
	if expandYAMLSafeActions(prose) != prose {
		t.Fatalf("prose comment changed: %q", expandYAMLSafeActions(prose))
	}
	if got, want := expandYAMLSafeActions(src), expandYAMLSafeActions(expandYAMLSafeActions(src)); got != want {
		t.Fatalf("expand is not idempotent\n%q", got)
	}

	on, err := ProcessTemplate([]byte(src), map[string]string{"Name": "hello", "Raw": "5", "On": "1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(on) != "key: hello\nnested: 5\nexpr: ${{ github.token }}\n" {
		t.Fatalf("included block:\n%q", on)
	}

	off, err := ProcessTemplate([]byte(src), map[string]string{"Name": "hello", "Raw": "5", "On": "0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(off) != "key: hello\nexpr: ${{ github.token }}\n" {
		t.Fatalf("omitted block:\n%q", off)
	}
}

func TestExpandYAMLSafeActionsLeavesUnrelatedText(t *testing.T) {
	inputs := []string{
		"key: \"{{ eq .X \"}}\" }}\"\n",
		"s := `\"{{ .NotARealField }}\"`\n",
		"# {{ .Name }}\n",
		"# \"{{ .Name }}\"\n",
		"echo \"{{ .Name }}\"\n",
		"key: \"{{ .Name }}\" trailing\n",
		"# {{- include .Name }}\n",
	}
	for _, src := range inputs {
		if got := expandYAMLSafeActions(src); got != src {
			t.Errorf("expand changed %q\ninto %q", src, got)
		}
	}

	comment, err := ProcessTemplate([]byte("# {{ .Name }}\n"), map[string]string{"Name": "hello"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(comment) != "# hello\n" {
		t.Fatalf("comment became a live action: %q", comment)
	}
	echo, err := ProcessTemplate([]byte("echo \"{{ .Name }}\"\n"), map[string]string{"Name": "hello"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(echo) != "echo \"hello\"\n" {
		t.Fatalf("echo quotes were stripped: %q", echo)
	}
}

func TestExpandLeavesUnmarkedTemplates(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		raw, err := os.ReadFile(filepath.Join("..", "..", "templates", name))
		if err != nil {
			t.Fatal(err)
		}
		got := expandYAMLSafeActions(string(raw))
		rewritten := name == "dependabot.yml" ||
			name == "dependency-review.yml" ||
			name == "dependency-artifact-review.yml"
		if rewritten {
			if got == string(raw) {
				t.Errorf("%s: expected YAML-safe actions to expand", name)
			}
			continue
		}
		if got != string(raw) {
			t.Errorf("%s: expand changed a template that has no YAML-safe actions", name)
		}
	}
}

// TestRenderedTemplatesMatchPreviousOutput compares rendered templates with
// the output from before the YAML-safe spellings, for templateRenderCases.
func TestRenderedTemplatesMatchPreviousOutput(t *testing.T) {
	cases := templateRenderCases(t)
	for _, file := range []string{"dependabot.yml", "dependency-review.yml"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "templates", file))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cases {
			if file == "dependency-review.yml" && (c.name == "groups-off" || c.name == "groups-on") {
				continue
			}
			got, err := ProcessTemplate(raw, c.vars, nil)
			if err != nil {
				t.Fatalf("%s %s: %v", file, c.name, err)
			}
			if file == "dependabot.yml" {
				pipRegistryAllowsCodeExecution(t, got)
			}
			want, err := os.ReadFile(filepath.Join("testdata", "render", file+"."+c.name))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Errorf("%s %s rendered output changed\n--- got ---\n%s\n--- want ---\n%s", file, c.name, got, want)
			}
			var doc any
			if err := yaml.Unmarshal(got, &doc); err != nil {
				t.Errorf("%s %s rendered YAML does not parse: %v", file, c.name, err)
			}
		}
	}
}

func TestTemplateActionPinsNotBehindWorkflows(t *testing.T) {
	templatePins := actionPins(t, filepath.Join("..", "..", "templates"))
	workflowPins := actionPins(t, filepath.Join("..", "..", ".github", "workflows"))
	for name, pins := range templatePins {
		for _, templateRef := range pins {
			templateVersion, ok := parseActionVersion(templateRef)
			if !ok {
				continue
			}
			for _, workflowRef := range workflowPins[name] {
				workflowVersion, ok := parseActionVersion(workflowRef)
				if !ok {
					continue
				}
				if versionBehind(templateVersion, workflowVersion) {
					t.Errorf("%s@%s in templates is behind %s@%s in .github/workflows", name, templateRef, name, workflowRef)
				}
			}
		}
	}
}

func TestActionVersionBehind(t *testing.T) {
	cases := []struct {
		template string
		workflow string
		behind   bool
	}{
		{template: "v7", workflow: "v8", behind: true},
		{template: "v8", workflow: "v7", behind: false},
		{template: "v7", workflow: "v7.0.0", behind: false},
		{template: "v7.0.0", workflow: "v7.1.0", behind: true},
		{template: "v7.2.0", workflow: "v7.1.9", behind: false},
		{template: "v5.0.0", workflow: "v5", behind: false},
	}
	for _, c := range cases {
		tv, ok := parseActionVersion(c.template)
		if !ok {
			t.Fatal(c.template)
		}
		wv, ok := parseActionVersion(c.workflow)
		if !ok {
			t.Fatal(c.workflow)
		}
		if got := versionBehind(tv, wv); got != c.behind {
			t.Errorf("versionBehind(%s, %s) = %v, want %v", c.template, c.workflow, got, c.behind)
		}
	}
	if _, ok := parseActionVersion("main"); ok {
		t.Fatal("branch refs are not versions")
	}
}

func TestThisRepoDependabotScansTemplates(t *testing.T) {
	cfg, err := config.LoadConfig(filepath.Join("..", "..", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg.Variables["DEPENDABOT_ACTIONS_DIRECTORIES"], "/templates") {
		t.Fatal("default action directories include /templates; opt in per repo")
	}

	var repoConfig Config
	raw, err := os.ReadFile(filepath.Join("..", "..", ".repo-content-updater.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &repoConfig); err != nil {
		t.Fatal(err)
	}
	override := repoConfig.VarOverrides["DEPENDABOT_ACTIONS_DIRECTORIES"]
	var fromOverride []string
	if err := yaml.Unmarshal([]byte(override), &fromOverride); err != nil {
		t.Fatal(err)
	}

	repoRoot := filepath.Join("..", "..")
	fileinfo := cfg.GetFileInfo("dependabot")
	template, err := os.ReadFile(filepath.Join(repoRoot, "templates", "dependabot.yml"))
	if err != nil {
		t.Fatal(err)
	}
	templateVars, err := DependabotVarsForRepo(repoRoot, cfg.Variables, repoConfig.VarOverrides)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProcessTemplate(template, withAdoptionMarker(templateVars, fileinfo.AdoptionMarker), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err = postRenderDependabot(repoRoot, false, fileinfo, got)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := os.ReadFile(filepath.Join(repoRoot, ".github", "dependabot.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, rendered) {
		t.Fatalf("rendered dependabot.yml does not match .github/dependabot.yml\n--- rendered ---\n%s\n--- committed ---\n%s", got, rendered)
	}
	fromRendered := githubActionsDirectories(t, rendered)
	if strings.Join(fromOverride, "\n") != strings.Join(fromRendered, "\n") {
		t.Fatalf("override %q renders differently from .github/dependabot.yml %q", fromOverride, fromRendered)
	}
	if strings.Join(fromRendered, "\n") != "/\n/.github/actions/*\n/templates" {
		t.Fatalf("directories = %#v", fromRendered)
	}
}

type templateRenderCase struct {
	name string
	vars map[string]string
}

func templateRenderCases(t *testing.T) []templateRenderCase {
	t.Helper()
	cfg, err := config.LoadConfig(filepath.Join("..", "..", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	base := map[string]string{}
	for k, v := range cfg.Variables {
		base[k] = v
	}
	clone := func(in map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range in {
			out[k] = v
		}
		return out
	}
	withGroups := func(value string) map[string]string {
		out := clone(base)
		for k := range out {
			if strings.HasSuffix(k, "GROUP_UPDATES") {
				out[k] = value
			}
		}
		return out
	}
	custom := clone(base)
	custom["DEPENDABOT_ACTIONS_DIRECTORIES"] = `["/", "/.github/actions/*", "/templates"]`
	custom["DEPENDABOT_GOMOD_PULL_REQUEST_LIMIT"] = "3"
	custom["DEPENDENCY_REVIEW_ALLOW_DEPENDENCIES_LICENSES"] = "pkg:pypi/example"
	custom["DEPENDABOT_DENY_LICENSES"] = "GPL-3.0-only, MIT"
	return []templateRenderCase{
		{name: "defaults", vars: base},
		{name: "groups-off", vars: withGroups("0")},
		{name: "groups-on", vars: withGroups("1")},
		{name: "custom", vars: custom},
	}
}

func actionPins(t *testing.T, dir string) map[string][]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	pins := map[string][]string{}
	for _, entry := range entries {
		if entry.IsDir() || !isYAMLName(entry.Name()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, uses := range usesValues(t, raw) {
			name, ref, ok := splitActionRef(uses)
			if !ok {
				continue
			}
			pins[name] = append(pins[name], ref)
		}
	}
	return pins
}

func usesValues(t *testing.T, raw []byte) []string {
	t.Helper()
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var found []string
	collectUses(doc, &found)
	return found
}

func collectUses(v any, found *[]string) {
	switch node := v.(type) {
	case map[string]any:
		for key, child := range node {
			if key == "uses" {
				if s, ok := child.(string); ok {
					*found = append(*found, s)
				}
			}
			collectUses(child, found)
		}
	case []any:
		for _, child := range node {
			collectUses(child, found)
		}
	}
}

func splitActionRef(uses string) (string, string, bool) {
	uses = strings.TrimSpace(uses)
	if uses == "" || strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://") {
		return "", "", false
	}
	at := strings.LastIndex(uses, "@")
	if at <= 0 || at == len(uses)-1 {
		return "", "", false
	}
	return strings.ToLower(uses[:at]), uses[at+1:], true
}

func parseActionVersion(ref string) ([]int, bool) {
	ref = strings.TrimPrefix(ref, "v")
	if ref == "" {
		return nil, false
	}
	parts := strings.Split(ref, ".")
	nums := make([]int, len(parts))
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		nums[i] = n
	}
	return nums, true
}

// versionBehind reports whether template is an older release than workflow.
// A shorter ref is a prefix, not an older release: v7 is not behind v7.1.0.
func versionBehind(template, workflow []int) bool {
	n := len(template)
	if len(workflow) < n {
		n = len(workflow)
	}
	for i := 0; i < n; i++ {
		if template[i] != workflow[i] {
			return template[i] < workflow[i]
		}
	}
	return false
}

func githubActionsDirectories(t *testing.T, raw []byte) []string {
	t.Helper()
	var doc struct {
		Updates []struct {
			Ecosystem   string   `yaml:"package-ecosystem"`
			Directories []string `yaml:"directories"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, update := range doc.Updates {
		if update.Ecosystem == "github-actions" {
			return update.Directories
		}
	}
	t.Fatal("github-actions update not found")
	return nil
}

func pipRegistryAllowsCodeExecution(t *testing.T, raw []byte) {
	t.Helper()
	var doc struct {
		Registries map[string]struct {
			Type string `yaml:"type"`
			URL  string `yaml:"url"`
		} `yaml:"registries"`
		Updates []struct {
			Ecosystem  string   `yaml:"package-ecosystem"`
			Registries []string `yaml:"registries"`
			CodeExec   string   `yaml:"insecure-external-code-execution"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for name, url := range map[string]string{
		"chia-pypi":      "https://pypi.chia.net/simple/",
		"chia-downloads": "https://download.chia.net/simple/",
	} {
		registry, ok := doc.Registries[name]
		if !ok || registry.Type != "python-index" || registry.URL != url {
			t.Errorf("registry %s = %#v, want python-index at %s", name, registry, url)
		}
	}
	pip := 0
	for _, update := range doc.Updates {
		if update.Ecosystem != "pip" {
			if len(update.Registries) != 0 {
				t.Errorf("%s references pip registries: %#v", update.Ecosystem, update.Registries)
			}
			if update.CodeExec != "" {
				t.Errorf("%s sets insecure-external-code-execution", update.Ecosystem)
			}
			continue
		}
		pip++
		if len(update.Registries) != 2 || update.Registries[0] != "chia-pypi" || update.Registries[1] != "chia-downloads" {
			t.Errorf("pip registries = %#v, want [chia-pypi chia-downloads]", update.Registries)
		}
		if update.CodeExec != "allow" {
			t.Errorf("pip insecure-external-code-execution = %q, want allow", update.CodeExec)
		}
	}
	if pip != 1 {
		t.Errorf("pip updates = %d, want 1", pip)
	}
}

func isYAMLName(name string) bool {
	return strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")
}

func actionUsesLines(src string) []string {
	var found []string
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimPrefix(trimmed, "- ")
		trimmed = strings.TrimSpace(trimmed)
		if !strings.HasPrefix(trimmed, "uses:") {
			continue
		}
		uses := strings.TrimSpace(strings.TrimPrefix(trimmed, "uses:"))
		if uses == "" || strings.HasPrefix(uses, "#") {
			continue
		}
		// A SHA pin carries its tag as a trailing comment, which YAML does not parse.
		uses, _, _ = strings.Cut(uses, " #")
		found = append(found, uses)
	}
	return found
}

func TestDependabotActionDirectoriesAreRepositoryRooted(t *testing.T) {
	snapshots, err := filepath.Glob(filepath.Join("testdata", "render", "dependabot.yml.*"))
	if err != nil {
		t.Fatal(err)
	}
	snapshots = append(snapshots, filepath.Join("..", "..", ".github", "dependabot.yml"))
	for _, path := range snapshots {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, dir := range githubActionsDirectories(t, raw) {
			if !strings.HasPrefix(dir, "/") {
				t.Errorf("%s: github-actions directory %q must start with /", path, dir)
			}
		}
	}
}
