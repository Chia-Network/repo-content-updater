package repo

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const artifactReviewTemplate = "dependency-artifact-review.yml"

func TestArtifactReviewPublishJobHasUniqueName(t *testing.T) {
	workflow := readArtifactReviewTemplate(t)
	if !strings.Contains(workflow, "\n  dependency-artifact-review:\n") {
		t.Fatal("missing dependency-artifact-review publish job")
	}
	if strings.Contains(workflow, "\n  dependency-review:\n") {
		t.Fatal("artifact review still reuses the dependency-review job id")
	}
}

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

func TestArtifactReviewAgentIsGatedOnReviewable(t *testing.T) {
	workflow := readArtifactReviewTemplate(t)
	prepare := artifactReviewJob(t, workflow, "prepare")
	if !strings.Contains(prepare, "id: fetch") ||
		!strings.Contains(prepare, "reviewable: ${{`{{ steps.fetch.outputs.reviewable }}`}}") {
		t.Fatal("prepare does not expose the reviewable output")
	}
	agent := artifactReviewJob(t, workflow, "agent")
	if !strings.Contains(agent, "if: ${{`{{ needs.prepare.outputs.reviewable == 'true' }}`}}") {
		t.Fatal("agent is not gated on reviewable")
	}
}

func TestArtifactReviewPublishStillCommentsOnFailure(t *testing.T) {
	workflow := readArtifactReviewTemplate(t)
	publish := artifactReviewJob(t, workflow, "dependency-artifact-review")
	if strings.Contains(publish, "Fail closed when prepare or agent failed") {
		t.Fatal("publish still exits before writing the comment")
	}
	for _, name := range []string{
		"Checkout trusted verdict script",
		"Set up Python",
		"Download verdict inputs",
		"Decide and compose comment",
		"Post or update PR comment",
		"Set the check result",
	} {
		if !strings.Contains(artifactReviewStep(t, publish, name), "if: ${{`{{ always()") {
			t.Errorf("%s does not run after an earlier failure", name)
		}
	}
	if !strings.Contains(artifactReviewStep(t, publish, "Download verdict inputs"), "continue-on-error: true") {
		t.Fatal("missing verdict inputs should not stop the verdict step")
	}
}

func TestArtifactReviewPublishDownloadsOnlyVerdictInputs(t *testing.T) {
	workflow := readArtifactReviewTemplate(t)
	prepare := artifactReviewJob(t, workflow, "prepare")
	metadata := artifactReviewStep(t, prepare, "Upload review metadata")
	if !strings.Contains(metadata, "name: dcr-verdict-meta-") || !strings.HasSuffix(strings.TrimSpace(metadata), "meta.json") {
		t.Fatal("prepare does not upload meta.json as a small artifact")
	}
	agent := artifactReviewJob(t, workflow, "agent")
	output := artifactReviewStep(t, agent, "Upload agent output")
	if !strings.Contains(output, "name: dcr-verdict-agent-") ||
		!strings.HasSuffix(strings.TrimSpace(output), "agent_output.txt") {
		t.Fatal("agent does not upload agent_output.txt as a small artifact")
	}
	publish := artifactReviewJob(t, workflow, "dependency-artifact-review")
	download := artifactReviewStep(t, publish, "Download verdict inputs")
	if !strings.Contains(download, "pattern: dcr-verdict-*") {
		t.Fatal("publish does not download the verdict artifacts")
	}
	if strings.Contains(publish, "dcr-review-input") {
		t.Fatal("publish downloads the full review bundle")
	}
}

func TestArtifactReviewCommentOnlyUpdatesTheActionsBot(t *testing.T) {
	workflow := readArtifactReviewTemplate(t)
	publish := artifactReviewJob(t, workflow, "dependency-artifact-review")
	post := artifactReviewStep(t, publish, "Post or update PR comment")
	if !strings.Contains(post, "comment.user?.type === 'Bot'") ||
		!strings.Contains(post, "comment.user?.login === 'github-actions[bot]'") {
		t.Fatal("comment lookup does not require the actions bot")
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

func artifactReviewJob(t *testing.T, workflow, name string) string {
	t.Helper()
	marker := "\n  " + name + ":\n"
	start := strings.Index(workflow, marker)
	if start < 0 {
		t.Fatalf("missing job %s", name)
	}
	start += len(marker)
	rest := workflow[start:]
	if next := regexp.MustCompile(`\n  [A-Za-z0-9_-]+:\n`).FindStringIndex(rest); next != nil {
		rest = rest[:next[0]]
	}
	return rest
}

func artifactReviewStep(t *testing.T, job, name string) string {
	t.Helper()
	marker := "      - name: " + name + "\n"
	start := strings.Index(job, marker)
	if start < 0 {
		t.Fatalf("missing step %s", name)
	}
	start += len(marker)
	rest := job[start:]
	if next := strings.Index(rest, "\n      - name:"); next >= 0 {
		rest = rest[:next]
	}
	return rest
}
