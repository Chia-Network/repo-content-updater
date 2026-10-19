package repo

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/chia-network/repo-content-updater/internal/config"
)

// TestAllTemplatesRender syncs formatter mirrors, then renders every file in
// templates/ through ProcessTemplate with the config.yaml variables. That is
// the path managed-files uses. Any parse or execute error fails the test.
func TestAllTemplatesRender(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "internal", "workflowscripts", "sync_malware_formatter_templates.py")
	cmd := exec.Command("python3", script)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sync_malware_formatter_templates.py: %v\n%s", err, out)
	}

	cfg, err := config.LoadConfig(filepath.Join(root, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	templates := filepath.Join(root, "templates")
	entries, err := os.ReadDir(templates)
	if err != nil {
		t.Fatal(err)
	}

	rendered := map[string]struct{}{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		raw, err := os.ReadFile(filepath.Join(templates, name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ProcessTemplate(raw, cfg.Variables, nil); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		rendered[name] = struct{}{}
	}
	if len(rendered) == 0 {
		t.Fatal("templates/ has no files after sync")
	}
	for _, file := range cfg.Files {
		if _, ok := rendered[file.TemplateName]; !ok {
			t.Errorf("config template %s missing from templates/ after sync", file.TemplateName)
		}
	}
}
