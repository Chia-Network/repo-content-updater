'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const WORKFLOW = fs.readFileSync(path.join(__dirname, '..', '..', 'templates', 'dependency-artifact-review.yml'), 'utf8');
const MARKER = '<!-- dcr-artifact-review -->';
const COMMENT_PATH = path.join(os.tmpdir(), 'dcr-comment.test.md');

function commentScript() {
  const marker = '          script: |\n';
  const lines = [];
  for (const line of WORKFLOW.slice(WORKFLOW.indexOf(marker) + marker.length).split('\n')) {
    if (line !== '' && !line.startsWith('            ')) break;
    lines.push(line.slice(12));
  }
  return lines.join('\n');
}

async function run(comments) {
  fs.writeFileSync(COMMENT_PATH, 'review body\n');
  process.env.COMMENT_PATH = COMMENT_PATH;
  process.env.PR_NUMBER = '12';
  const calls = [];
  const github = { paginate: async () => comments, rest: { issues: {
    createComment: async (issue) => calls.push(['create', issue]),
    updateComment: async (issue) => calls.push(['update', issue]),
  } } };
  const body = `'use strict'; return (async () => {\n${commentScript()}\n})();`;
  await new Function('require', 'github', 'core', 'context', body)(require, github, { setFailed: () => {} }, {
    repo: { owner: 'owner', repo: 'repo' },
  });
  return calls;
}

const bot = (id) => ({
  id,
  body: MARKER,
  created_at: `2026-10-2${id}T00:00:00Z`,
  user: { type: 'Bot', login: 'github-actions[bot]' },
});

test('creates a comment when none has the marker', async () => {
  const calls = await run([{ id: 9, body: 'other', user: { type: 'User', login: 'someone' } }]);
  assert.deepEqual(calls.map(([kind]) => kind), ['create']);
});

test('updates the latest comment with the marker', async () => {
  const calls = await run([bot(1), bot(2)]);
  assert.deepEqual(calls.map(([kind]) => kind), ['update']);
  assert.equal(calls[0][1].comment_id, 2);
});
