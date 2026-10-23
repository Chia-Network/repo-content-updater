'use strict';

// The already-reviewed skip rule. A later refactor must keep this contract.

const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const test = require('node:test');

const {
  reviewMarkerFromPatchId,
  reviewedShasForPatch,
  skipApplies,
} = require('./dependency-cursor-review-dependabot-context.js');

const PATCH = 'a'.repeat(40);
const OTHER_PATCH = 'c'.repeat(40);
const RESOLVED = 'b'.repeat(40);
const MOVED = 'd'.repeat(40);

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

test('the workflow applies the skip rule with the patch-id and the resolved commit', () => {
  const workflow = fs.readFileSync(
    path.join(__dirname, '..', '..', 'templates', 'dependency-cursor-review.yml'),
    'utf8',
  );
  assert.match(workflow, /skipApplies\(reviewed, patchId, resolved\)/);
  assert.match(workflow, /const patchId = process\.env\.PATCH_ID \|\| '';/);
  assert.match(workflow, /const resolved = process\.env\.RESOLVED_TO \|\| '';/);
});
