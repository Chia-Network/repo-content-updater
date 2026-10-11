package config_test

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const scanReportName = "malware_scan_report.json"

func TestWorkflowFreezesScanReportBeforeAgents(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", "..", "templates", "dependency-cursor-review.yml"))
	require.NoError(t, err)
	text := string(workflow)

	copyReport := `cp malware_scan_report.json "${trusted_root}/malware_scan_report.json"`
	copyIdx := strings.Index(text, copyReport)
	snapshotIdx := strings.Index(text, "trusted_hash_snapshot=")
	agentIdx := strings.Index(text, `run_agent_prompt "cursor_prompt_malware.txt"`)
	compareIdx := strings.Index(text, `if [ "$trusted_hash_now" != "$trusted_hash_snapshot" ]`)
	combineIdx := strings.LastIndex(text, "dependency_cursor_review_combine_outputs.py")

	require.NotEqual(t, -1, copyIdx)
	require.NotEqual(t, -1, snapshotIdx)
	require.NotEqual(t, -1, agentIdx)
	require.NotEqual(t, -1, compareIdx)
	require.NotEqual(t, -1, combineIdx)
	require.Less(t, copyIdx, snapshotIdx)
	require.Less(t, snapshotIdx, agentIdx)
	require.Less(t, agentIdx, compareIdx)
	require.Less(t, compareIdx, combineIdx)
	require.Contains(t, text, `export TRUSTED_DCR_SCRIPTS_SHA256="$trusted_hash_snapshot"`)
	require.Contains(t, text, `find "$trusted_root" -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum`)
	require.NotContains(t, text, "cmp -s")
}

func TestFrozenScanReportTamperFailsClosed(t *testing.T) {
	inconclusive := []byte(`{"status":"not_scanned","scan_conclusive":false,"verdict_token_in_tree":false}` + "\n")
	conclusive := []byte(`{"status":"clean","scan_conclusive":true,"verdict_token_in_tree":false}` + "\n")

	t.Run("intact inconclusive report ignores workspace fake", func(t *testing.T) {
		root, workspace := frozenScanLayout(t, inconclusive)
		code, output := runFrozenCombine(t, root, workspace, trustedTreeManifest(t, root))
		require.Equal(t, 0, code, output)
		assertInconclusiveVerdict(t, workspace)
	})

	t.Run("flip scan_conclusive", func(t *testing.T) {
		root, workspace := frozenScanLayout(t, inconclusive)
		manifest := trustedTreeManifest(t, root)
		flipScanConclusive(t, filepath.Join(root, scanReportName))
		assertTamperFailed(t, root, workspace, manifest)
	})

	t.Run("delete report", func(t *testing.T) {
		root, workspace := frozenScanLayout(t, inconclusive)
		manifest := trustedTreeManifest(t, root)
		require.NoError(t, os.Remove(filepath.Join(root, scanReportName)))
		assertTamperFailed(t, root, workspace, manifest)
	})

	t.Run("swap fake report", func(t *testing.T) {
		root, workspace := frozenScanLayout(t, inconclusive)
		manifest := trustedTreeManifest(t, root)
		require.NoError(t, os.WriteFile(filepath.Join(root, scanReportName), conclusive, 0o644))
		assertTamperFailed(t, root, workspace, manifest)
	})
}

func assertTamperFailed(t *testing.T, root, workspace, manifest string) {
	t.Helper()
	code, output := runFrozenCombine(t, root, workspace, manifest)
	require.NotEqual(t, 0, code, output)
	require.Contains(t, output, "changed before combine")
	_, err := os.Stat(filepath.Join(workspace, "cursor_output.json"))
	require.True(t, os.IsNotExist(err))
}

func assertInconclusiveVerdict(t *testing.T, workspace string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(workspace, "cursor_output.json"))
	require.NoError(t, err)
	var combined map[string]any
	require.NoError(t, json.Unmarshal(data, &combined))
	result, _ := combined["result"].(string)
	require.Contains(t, result, "**Verdict: inconclusive (needs human review)**")
	require.NotContains(t, result, "**Verdict: benign**")
}

func frozenScanLayout(t *testing.T, report []byte) (string, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "trusted-dcr-scripts")
	scripts := filepath.Join(root, ".github", "scripts")
	require.NoError(t, os.MkdirAll(scripts, 0o755))
	source := filepath.Join("..", "workflowscripts")
	for _, name := range []string{
		"scripts_dir_disk_exec.py",
		"scripts_dir_path_scrub.py",
		"isolated_module_exec.py",
		"trusted_formatter_loader.py",
		"trusted_formatter_loader_cold_start.py",
		"formatter_runtime_bundle.py",
		"malware_verdict_formatter.py",
		"dependency_cursor_review_combine_outputs.py",
	} {
		data, err := os.ReadFile(filepath.Join(source, name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(scripts, name), data, 0o644))
	}
	if report != nil {
		require.NoError(t, os.WriteFile(filepath.Join(root, scanReportName), report, 0o644))
	}

	workspace := filepath.Join(base, "workspace")
	require.NoError(t, os.MkdirAll(workspace, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(workspace, "cursor_output_malware.json"),
		[]byte(`{"result":"MALWARE_REVIEW_VERDICT: benign\n\nNo IOCs."}`),
		0o644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(workspace, "cursor_output_compatibility.json"),
		[]byte(`{"result":"compat ok"}`),
		0o644,
	))
	// Workspace copy claims a conclusive clean scan. Combine must ignore it.
	require.NoError(t, os.WriteFile(
		filepath.Join(workspace, scanReportName),
		[]byte(`{"status":"clean","scan_conclusive":true,"verdict_token_in_tree":false}`+"\n"),
		0o644,
	))
	return root, workspace
}

func trustedTreeManifest(t *testing.T, root string) string {
	t.Helper()
	cmd := exec.Command(
		"bash",
		"-c",
		`root="$(cd "$1" && pwd -P)" || exit 1
find "$root" -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum`,
		"hash_trusted_scripts",
		root,
	)
	out, err := cmd.Output()
	require.NoError(t, err, string(out))
	return strings.TrimRight(string(out), "\n")
}

func runFrozenCombine(t *testing.T, root, workspace, manifest string) (int, string) {
	t.Helper()
	script := filepath.Join(root, ".github", "scripts", "dependency_cursor_review_combine_outputs.py")
	cmd := exec.Command("python3", "-I", script)
	cmd.Dir = workspace
	env := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "TRUSTED_DCR_SCRIPTS_SHA256=") {
			env = append(env, entry)
		}
	}
	cmd.Env = append(env, "TRUSTED_DCR_SCRIPTS_SHA256="+manifest)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), string(out)
	}
	t.Fatalf("combine: %v\n%s", err, out)
	return -1, string(out)
}

func flipScanConclusive(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var report map[string]any
	require.NoError(t, json.Unmarshal(data, &report))
	report["scan_conclusive"] = true
	encoded, err := json.Marshal(report)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, append(encoded, '\n'), 0o644))
}
