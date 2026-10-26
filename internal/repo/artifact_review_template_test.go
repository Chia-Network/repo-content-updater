package repo

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const artifactReviewTemplate = "dependency-artifact-review.yml"

func TestArtifactReviewActionsArePinned(t *testing.T) {
	workflow := readArtifactReviewTemplate(t)
	pins := map[string]bool{}
	usesLine := regexp.MustCompile(`(?m)^\s+uses:\s+(\S+)\s+(#\s*v[0-9][^\n]*)$`)
	for _, match := range usesLine.FindAllStringSubmatch(workflow, -1) {
		name, ref, ok := splitActionRef(match[1])
		if !ok {
			continue
		}
		if len(ref) != 40 || strings.Trim(ref, "0123456789abcdef") != "" {
			t.Errorf("%s@%s is not a 40-hex commit SHA", name, ref)
		}
		pins[name+"@"+ref] = true
	}
	for _, want := range []string{
		"actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
		"actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
		"actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",
		"actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3",
		"dependabot/fetch-metadata@21025c705c08248db411dc16f3619e6b5f9ea21a",
		"actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",
	} {
		if !pins[want] {
			t.Errorf("missing pinned action %s", want)
		}
	}
}

func TestArtifactReviewDoesNotPipeACurlInstallerToAShell(t *testing.T) {
	workflow := readArtifactReviewTemplate(t)
	if strings.Contains(workflow, "cursor.com/install") {
		t.Fatal("artifact review still uses the cursor.com installer")
	}
	if regexp.MustCompile(`curl[^\n]*\|\s*(?:bash|sh)\b`).MatchString(workflow) {
		t.Fatal("artifact review pipes curl to a shell")
	}
	if !strings.Contains(workflow, "https://downloads.cursor.com/lab/${CURSOR_CLI_VERSION}/linux/x64/agent-cli-package.tar.gz") {
		t.Fatal("missing pinned Cursor CLI tarball URL")
	}
	if !strings.Contains(workflow, "sha256sum -c -") || !strings.Contains(workflow, "tar --strip-components=1 -xzf") {
		t.Fatal("Cursor CLI tarball is not verified and extracted as expected")
	}
}

func readArtifactReviewTemplate(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "templates", artifactReviewTemplate))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
