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

function bindReviewScript() {
  const workflow = fs.readFileSync(
    path.join(__dirname, '..', '..', 'templates', 'dependency-cursor-review.yml'),
    'utf8',
  );
  const step = workflow.split('\n      - name: ').find((block) => block.includes('id: bind_review'));
  assert.ok(step, 'bind_review step is present');
  const [, script] = step.split('script: |\n');
  return script
    .split('\n')
    .filter((line) => line.startsWith('            ') || !line.trim())
    .map((line) => line.slice(12))
    .join('\n');
}

test('the bind_review workflow step publishes bindReviewOutputs for its env', () => {
  const runnerTemp = fs.mkdtempSync(path.join(os.tmpdir(), 'dcr-bind-'));
  fs.symlinkSync(__dirname, path.join(runnerTemp, 'trusted-dcr-scripts'));
  try {
    for (const { env, want } of [BIND_CASES[0], BIND_CASES[2]]) {
      const outputs = {};
      const core = { setOutput: (name, value) => { outputs[name] = value; } };
      const fakeProcess = { env: { ...env, RUNNER_TEMP: runnerTemp } };
      new Function('core', 'process', 'require', bindReviewScript())(core, fakeProcess, require);
      assert.deepEqual(outputs, want);
    }
  } finally {
    fs.rmSync(runnerTemp, { recursive: true, force: true });
  }
});
