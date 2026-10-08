package repo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileModeForContent(t *testing.T) {
	if got := FileModeForContent([]byte("#!/usr/bin/env bash\necho hi\n")); got != 0o755 {
		t.Fatalf("shebang mode = %o, want 0755", got)
	}
	if got := FileModeForContent([]byte("from __future__ import annotations\n")); got != 0o644 {
		t.Fatalf("module mode = %o, want 0644", got)
	}
	if got := FileModeForContent([]byte(" #!/bin/sh\n")); got != 0o644 {
		t.Fatalf("commented shebang mode = %o, want 0644", got)
	}
}

func TestWriteManagedContentChmodsExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".github", "scripts", "tool.sh")
	script := []byte("#!/usr/bin/env bash\necho ok\n")

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	// Existing non-executable file: WriteFile alone would keep 0644.
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeManagedContent(path, script); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("updated shebang perm = %o, want 0755", info.Mode().Perm())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(script) {
		t.Fatalf("content = %q", body)
	}

	module := []byte("from __future__ import annotations\n")
	if err := writeManagedContent(path, module); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("updated module perm = %o, want 0644", info.Mode().Perm())
	}
}
