package repo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/chia-network/repo-content-updater/internal/config"
)

func TestDependencyReviewSkipsPrivateRepositories(t *testing.T) {
	root := filepath.Join("..", "..")
	cfg, err := config.LoadConfig(filepath.Join(root, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "templates", "dependency-review.yml"))
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := ProcessTemplate(raw, cfg.Variables, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(rendered, &doc); err != nil {
		t.Fatal(err)
	}
	jobs := mappingValue(documentRoot(&doc), "jobs")
	if jobs == nil {
		t.Fatal("dependency-review.yml has no jobs mapping")
	}

	dependencyReview := mappingValue(mappingValue(jobs, "dependency-review"), "if")
	if dependencyReview == nil || dependencyReview.Kind != yaml.ScalarNode {
		t.Fatal("dependency-review job has no if scalar")
	}
	if !strings.Contains(dependencyReview.Value, "!github.event.repository.private") {
		t.Errorf("dependency-review if = %q, want it to skip private repositories", dependencyReview.Value)
	}
	if !strings.Contains(dependencyReview.Value, "github.repository_owner == 'Chia-Network'") {
		t.Errorf("dependency-review if = %q, want the Chia-Network owner check", dependencyReview.Value)
	}
	assertUnquotedScalar(t, "dependency-review", dependencyReview)

	osvScanner := mappingValue(mappingValue(jobs, "osv-scanner"), "if")
	if osvScanner == nil || osvScanner.Kind != yaml.ScalarNode {
		t.Fatal("osv-scanner job has no if scalar")
	}
	if osvScanner.Value != "github.repository_owner == 'Chia-Network'" {
		t.Errorf("osv-scanner if = %q, want it unchanged", osvScanner.Value)
	}
	assertUnquotedScalar(t, "osv-scanner", osvScanner)
}

func assertUnquotedScalar(t *testing.T, name string, node *yaml.Node) {
	t.Helper()
	if node.Style&yaml.DoubleQuotedStyle != 0 || node.Style&yaml.SingleQuotedStyle != 0 {
		t.Errorf("%s if is quoted in YAML: %q", name, node.Value)
	}
}
