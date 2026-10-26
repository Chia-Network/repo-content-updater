'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const WORKFLOW = path.join(__dirname, '..', '..', 'templates', 'dependency-artifact-review.yml');

function inlineCommentScript() {
  const workflow = fs.readFileSync(WORKFLOW, 'utf8');
  const step = workflow.indexOf('      - name: Post or update PR comment\n');
  assert.ok(step >= 0, 'artifact review workflow must post the review comment');
  const marker = '          script: |\n';
  const start = workflow.indexOf(marker, step);
  assert.ok(start >= 0, 'comment step must run an inline script');
  const lines = [];
  for (const line of workflow.slice(start + marker.length).split('\n')) {
    if (line !== '' && !line.startsWith('            ')) break;
    lines.push(line.slice(12));
  }
  return lines.join('\n');
}

const SCRIPT = inlineCommentScript();

async function runComment({ comments, marker, prNumber }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dcr-comment-'));
  const commentPath = path.join(dir, 'comment.md');
  fs.writeFileSync(commentPath, 'review body\n');
  const calls = [];
  const failures = [];
  const info = [];
  const github = {
    paginate: async () => comments,
    rest: {
      issues: {
        listComments: async () => undefined,
        createComment: async (issue) => calls.push(['create', issue]),
        updateComment: async (issue) => calls.push(['update', issue]),
      },
    },
  };
  const core = {
    setFailed: (message) => failures.push(message),
    info: (message) => info.push(message),
  };
  const previous = {
    COMMENT_PATH: process.env.COMMENT_PATH,
    REVIEW_MARKER: process.env.REVIEW_MARKER,
    PR_NUMBER: process.env.PR_NUMBER,
  };
  process.env.COMMENT_PATH = commentPath;
  process.env.REVIEW_MARKER = marker;
  process.env.PR_NUMBER = prNumber;
  try {
    const body = `'use strict'; return (async () => {\n${SCRIPT}\n})();`;
    await new Function('require', 'github', 'core', 'context', body)(require, github, core, {
      repo: { owner: 'owner', repo: 'repo' },
    });
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
  return { calls, failures, info };
}

const botComment = (body, id) => ({
  id,
  body,
  created_at: `2026-10-2${id}T00:00:00Z`,
  user: { type: 'Bot', login: 'github-actions[bot]' },
});

test('creates a comment when the workflow has not posted one', async () => {
  const { calls, failures } = await runComment({ comments: [], marker: 'marker-a', prNumber: '12' });
  assert.deepEqual(failures, []);
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], 'create');
  assert.equal(calls[0][1].issue_number, 12);
  assert.equal(calls[0][1].body, 'review body\n');
});

test('updates the latest review comment when the marker is new', async () => {
  const comments = [
    botComment('<!-- dcr-artifact-review sha256:old -->\nold', 1),
    botComment('<!-- dcr-artifact-review sha256:older -->\nolder', 2),
  ];
  const { calls } = await runComment({ comments, marker: 'marker-b', prNumber: '12' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], 'update');
  assert.equal(calls[0][1].comment_id, 2);
});

test('skips a review whose marker is already posted', async () => {
  const marker = 'marker-c';
  const comments = [botComment(`<!-- dcr-artifact-review sha256:new -->\n${marker}`, 1)];
  const { calls, info } = await runComment({ comments, marker, prNumber: '12' });
  assert.deepEqual(calls, []);
  assert.equal(info.length, 1);
});

test('fails when no pull request number is available', async () => {
  const { calls, failures } = await runComment({ comments: [], marker: 'marker-d', prNumber: '' });
  assert.deepEqual(calls, []);
  assert.deepEqual(failures, ['No PR number was resolved.']);
});
