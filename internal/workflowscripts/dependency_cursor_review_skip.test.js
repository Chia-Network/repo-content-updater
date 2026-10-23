'use strict';

// The already-reviewed skip rule. A later refactor must keep this contract.

const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');

const {
  bindReviewOutputs,
  reviewMarkerFromPatchId,
  reviewedShasForPatch,
  skipApplies,
} = require('./dependency-cursor-review-dependabot-context.js');

const PATCH = 'a'.repeat(40);
const OTHER_PATCH = 'c'.repeat(40);
const RESOLVED = 'b'.repeat(40);
const MOVED = 'd'.repeat(40);
const MARKER = reviewMarkerFromPatchId(PATCH, RESOLVED);

function botMarker(patchId, resolvedSha, login = 'github-actions[bot]') {
  return { user: { login }, body: `${reviewMarkerFromPatchId(patchId, resolvedSha)}\n## Review\n` };
}

function skips(comments, patchId, resolvedSha) {
  return skipApplies(reviewedShasForPatch(comments, patchId), patchId, resolvedSha);
}

test('grouped already-reviewed PR skips only on the same patch-id and the same resolved SHA', () => {
  const reviewed = [botMarker(PATCH, RESOLVED)];
  assert.equal(skips(reviewed, PATCH, RESOLVED), true);
  assert.equal(skips(reviewed, PATCH, MOVED), false, 'a moved resolved commit is reviewed again');
  assert.equal(skips(reviewed, OTHER_PATCH, RESOLVED), false, 'a different patch-id is reviewed again');
  assert.equal(skips(reviewed, '', RESOLVED), false, 'a missing patch-id is reviewed again');
  assert.equal(skips(reviewed, PATCH, ''), false, 'a missing resolved commit is reviewed again');
  assert.equal(skips(reviewed, PATCH, 'B'.repeat(40)), false, 'a non-canonical SHA is reviewed again');
  assert.equal(skips([botMarker(PATCH, RESOLVED, 'mallory')], PATCH, RESOLVED), false, 'only bot markers count');
  assert.equal(skips([], PATCH, RESOLVED), false);
  assert.equal(skipApplies([RESOLVED], '', RESOLVED), false, 'the rule checks the patch-id itself');
  assert.equal(skipApplies('not-a-list', PATCH, RESOLVED), false);
});

const BIND_CASES = [
  {
    name: 'same patch-id and same resolved SHA skips',
    env: { PATCH_ID: PATCH, REVIEWED_SHAS: RESOLVED, RESOLVED_TO: RESOLVED },
    want: { review_marker: MARKER, already_reviewed: 'true' },
  },
  {
    name: 'grouped PR already reviewed at this SHA skips',
    env: { PATCH_ID: PATCH, REVIEWED_SHAS: `${MOVED},${RESOLVED},`, RESOLVED_TO: RESOLVED },
    want: { review_marker: MARKER, already_reviewed: 'true' },
  },
  {
    name: 'moved resolved SHA reviews again',
    env: { PATCH_ID: PATCH, REVIEWED_SHAS: RESOLVED, RESOLVED_TO: MOVED },
    want: { review_marker: reviewMarkerFromPatchId(PATCH, MOVED), already_reviewed: 'false' },
  },
  {
    name: 'missing patch-id reviews again',
    env: { REVIEWED_SHAS: RESOLVED, RESOLVED_TO: RESOLVED },
    want: { review_marker: '', already_reviewed: 'false' },
  },
  {
    name: 'non-canonical resolved SHA reviews again',
    env: { PATCH_ID: PATCH, REVIEWED_SHAS: 'B'.repeat(40), RESOLVED_TO: 'B'.repeat(40) },
    want: { review_marker: '', already_reviewed: 'false' },
  },
  {
    name: 'non-canonical patch-id reviews again',
    env: { PATCH_ID: 'A'.repeat(40), REVIEWED_SHAS: RESOLVED, RESOLVED_TO: RESOLVED },
    want: { review_marker: '', already_reviewed: 'false' },
  },
  {
    name: 'no reviewed SHAs reviews',
    env: { PATCH_ID: PATCH, REVIEWED_SHAS: '', RESOLVED_TO: RESOLVED },
    want: { review_marker: MARKER, already_reviewed: 'false' },
  },
];

for (const { name, env, want } of BIND_CASES) {
  test(`bindReviewOutputs: ${name}`, () => {
    assert.deepEqual(bindReviewOutputs(env), want);
  });
}

// The bind_review step as the workflow wires it: its env: block maps step
// outputs to variables, and an output the run did not set reads as ''.
function bindReviewStep() {
  const workflow = fs.readFileSync(
    path.join(__dirname, '..', '..', 'templates', 'dependency-cursor-review.yml'),
    'utf8',
  );
  const step = workflow.split('\n      - name: ').find((block) => block.includes('id: bind_review'));
  assert.ok(step, 'bind_review step is present');
  const [, envBlock] = step.split('\n        env:\n');
  const wiring = envBlock
    .split('\n        with:\n')[0]
    .split('\n')
    .map((line) => {
      const match = /^ {10}([A-Z_]+): \$\{\{`\{\{ steps\.(\w+)\.outputs\.(\w+) \}\}`\}\}$/.exec(line);
      assert.ok(match, `bind_review env line reads a step output: ${line}`);
      return match.slice(1);
    });
  const [, script] = step.split('script: |\n');
  return {
    env: (outputs) => Object.fromEntries(wiring.map(([name, id, key]) => [name, outputs[id]?.[key] ?? ''])),
    script: script
      .split('\n')
      .filter((line) => line.startsWith('            ') || !line.trim())
      .map((line) => line.slice(12))
      .join('\n'),
  };
}

test('the bind_review workflow step publishes bindReviewOutputs for the step outputs it reads', () => {
  const step = bindReviewStep();
  const runnerTemp = fs.mkdtempSync(path.join(os.tmpdir(), 'dcr-bind-'));
  fs.symlinkSync(__dirname, path.join(runnerTemp, 'trusted-dcr-scripts'));
  const target_pr = { patch_id: PATCH, reviewed_shas: RESOLVED };
  try {
    for (const [resolved_to, want] of [
      [RESOLVED, BIND_CASES[0].want],
      [MOVED, BIND_CASES[2].want],
    ]) {
      const outputs = {};
      const core = { setOutput: (name, value) => { outputs[name] = value; } };
      const env = step.env({ target_pr, malware_scan: { resolved_to } });
      const fakeProcess = { env: { ...env, RUNNER_TEMP: runnerTemp } };
      new Function('core', 'process', 'require', step.script)(core, fakeProcess, require);
      assert.deepEqual(outputs, want);
    }
  } finally {
    fs.rmSync(runnerTemp, { recursive: true, force: true });
  }
});
