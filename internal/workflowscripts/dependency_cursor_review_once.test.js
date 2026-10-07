'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const context = require('./dependency-cursor-review-dependabot-context.js');
const { run } = require('./dependency-cursor-review-target-pr.js');
const postComment = require('./dependency-cursor-review-post-comment.js');

const { parseDependencyUpdate, reviewMarkerForUpgrade } = context;

function fakeCore() {
  return {
    outputs: {},
    failed: '',
    notices: [],
    warnings: [],
    setOutput(key, value) {
      this.outputs[key] = value;
    },
    setFailed(message) {
      this.failed = message;
    },
    notice(message) {
      this.notices.push(message);
    },
    warning(message) {
      this.warnings.push(message);
    },
    info() {},
  };
}

function singleBody(sha) {
  return [
    'Bumps [lodash](https://github.com/lodash/lodash) from 4.17.20 to 4.17.21.',
    '<details><summary>Release notes</summary>',
    'Ships a small patch.',
    '</details>',
    '<details><summary>Commits</summary>',
    `<li>${sha} fix something</li>`,
    '</details>',
  ].join('\n');
}

function groupBody(sha, bumps) {
  const sections = bumps.map(([name, from, to]) =>
    [`Updates \`${name}\` from ${from} to ${to}`, '<details><summary>Commits</summary>', sha, '</details>'].join('\n'),
  );
  return `Bumps the npm_and_yarn group with ${bumps.length} updates.\n\n${sections.join('\n\n')}`;
}

function payloadOf(marker) {
  const encoded = String(marker).match(/<!-- cursor-dependabot-review (\S+) -->/);
  assert.ok(encoded, marker);
  return Buffer.from(encoded[1], 'base64').toString('utf8');
}

function botComment(marker) {
  return {
    id: 1,
    user: { login: 'github-actions[bot]' },
    body: `${marker}\n## review`,
    created_at: '2026-01-01T00:00:00Z',
  };
}

function fakeGithub({ pr, commentsFor = () => [], listError }) {
  const calls = [];
  return {
    calls,
    rest: {
      pulls: {
        async get(params) {
          calls.push(['pulls.get', params]);
          return { data: pr };
        },
      },
      issues: {
        async listComments(params) {
          calls.push(['listComments', params]);
          if (listError) throw listError;
          return commentsFor(params.issue_number);
        },
        async updateComment(params) {
          calls.push(['updateComment', params]);
          return params;
        },
        async createComment(params) {
          calls.push(['createComment', params]);
          return params;
        },
      },
    },
    async paginate(fn, params) {
      return fn(params);
    },
  };
}

async function resolve(eventName, pr, options = {}) {
  const core = fakeCore();
  const github = fakeGithub({ pr, ...options });
  const payload =
    eventName === 'pull_request'
      ? { pull_request: pr }
      : { inputs: options.inputs || { pr_number: String(pr.number) } };
  await run({
    github,
    context: { eventName, repo: { owner: 'acme', repo: 'widgets' }, payload },
    core,
  });
  return { core, github };
}

async function withWorkspace(fn) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'dcr-'));
  const previous = process.cwd();
  const keys = ['PR_TITLE', 'PR_BODY', 'PR_NUMBER', 'REVIEW_MARKER'];
  const saved = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  process.chdir(directory);
  try {
    await fn(directory);
  } finally {
    process.chdir(previous);
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test('marker ignores rebase SHAs and from-version, and changes with the target', () => {
  const title = 'Bump lodash from 4.17.20 to 4.17.21';
  const same = reviewMarkerForUpgrade('Bump lodash from 4.17.19 to 4.17.21', singleBody('bbbbbbbbbbb'));
  const marker = reviewMarkerForUpgrade(title, singleBody('aaaaaaaaaaa'));
  assert.equal(marker, same);
  assert.equal(marker.includes('\n'), false);
  const payload = payloadOf(marker);
  assert.equal(payload.includes('aaaaaaaaaaa'), false);
  assert.equal(payload.includes('4.17.20'), false);
  assert.equal(payload.includes('4.17.21'), true);
  assert.notEqual(marker, reviewMarkerForUpgrade('Bump lodash from 4.17.20 to 4.17.22', singleBody('abc1234')));
});

test('group marker ignores commit SHAs and follows every Updates line', () => {
  const bumps = [
    ['brace-expansion', '2.0.1', '2.0.2'],
    ['minimatch', '9.0.3', '9.0.5'],
  ];
  const title = 'Bump the npm_and_yarn group with 2 updates';
  const marker = reviewMarkerForUpgrade(title, groupBody('1111111', bumps));
  assert.equal(marker, reviewMarkerForUpgrade(title, groupBody('2222222', bumps)));
  const payload = payloadOf(marker);
  assert.equal(payload.includes('1111111'), false);
  assert.match(payload, /minimatch/);
  assert.match(payload, /2\.0\.2/);
  const changed = reviewMarkerForUpgrade(
    title,
    groupBody('1111111', [
      ['brace-expansion', '2.0.1', '2.0.2'],
      ['minimatch', '9.0.3', '9.0.6'],
    ]),
  );
  assert.notEqual(marker, changed);
});

test('several Updates lines beat a title that names one package', () => {
  const body = [
    'Bumps [lodash](https://github.com/lodash/lodash) from 4.17.20 to 4.17.21.',
    'Updates `lodash` from 4.17.20 to 4.17.21',
    'Updates `semver` from 7.5.0 to 7.6.0',
  ].join('\n');
  const payload = payloadOf(reviewMarkerForUpgrade('Bump lodash from 4.17.20 to 4.17.21', body));
  assert.match(payload, /semver\t7\.6\.0/);
});

test('parseDependencyUpdate still extracts upstream notes and commits', () => {
  const parsed = parseDependencyUpdate('Bump lodash from 4.17.20 to 4.17.21', singleBody('deadbee'));
  assert.equal(parsed.upstreamRepo, 'lodash/lodash');
  assert.equal(parsed.packageName, 'lodash');
  assert.equal(parsed.toVersion, '4.17.21');
  assert.match(parsed.releaseNotes, /small patch/);
  assert.match(parsed.commits, /deadbee/);
});

test('context JSON stays limited to the prompt fields', async () => {
  await withWorkspace(async (directory) => {
    process.env.PR_TITLE = 'Bump lodash from 4.17.20 to 4.17.21';
    process.env.PR_BODY = singleBody('abc1234');
    process.env.PR_NUMBER = '42';
    const core = fakeCore();
    await context({ core });
    const written = JSON.parse(fs.readFileSync(path.join(directory, 'dependabot_comment_context.json'), 'utf8'));
    assert.deepEqual(Object.keys(written), [
      'prNumber',
      'upstreamRepo',
      'packageName',
      'fromVersion',
      'toVersion',
      'releaseNotes',
      'commits',
    ]);
    assert.equal(core.failed, '');
  });
});

test('rebase of the same Dependabot upgrade does not review again', async () => {
  const title = 'Bump lodash from 4.17.20 to 4.17.21';
  const marker = reviewMarkerForUpgrade(title, singleBody('aaaaaaaaaaa'));
  const pr = {
    number: 42,
    title,
    body: singleBody('bbbbbbbbbbb'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'newheadsha' },
  };
  const { core, github } = await resolve('pull_request', pr, { commentsFor: () => [botComment(marker)] });
  assert.equal(core.outputs.already_reviewed, 'true');
  assert.equal(core.outputs.review_marker, marker);
  assert.equal(core.outputs.head_sha, 'newheadsha');
  assert.equal(github.calls.find((call) => call[0] === 'listComments')[1].issue_number, 42);
});

test('a new pull request is reviewed even for a version reviewed elsewhere', async () => {
  const previous = reviewMarkerForUpgrade('Bump lodash from 4.17.20 to 4.17.21', singleBody('abc1234'));
  const pr = {
    number: 99,
    title: 'Bump lodash from 4.17.20 to 4.17.22',
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const { core } = await resolve('pull_request', pr, {
    commentsFor: (number) => (number === 42 ? [botComment(previous)] : []),
  });
  assert.equal(core.outputs.already_reviewed, 'false');
});

test('same pull request with a new target version is reviewed again', async () => {
  const oldMarker = reviewMarkerForUpgrade('Bump lodash from 4.17.20 to 4.17.21', singleBody('abc1234'));
  const pr = {
    number: 42,
    title: 'Bump lodash from 4.17.20 to 4.17.22',
    body: singleBody('def5678'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head2' },
  };
  const { core } = await resolve('pull_request', pr, { commentsFor: () => [botComment(oldMarker)] });
  assert.equal(core.outputs.already_reviewed, 'false');
});

test('a forged marker or a legacy marker does not suppress the review', async () => {
  const title = 'Bump lodash from 4.17.20 to 4.17.21';
  const marker = reviewMarkerForUpgrade(title, singleBody('abc1234'));
  const pr = {
    number: 42,
    title,
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const forged = await resolve('pull_request', pr, {
    commentsFor: () => [{ id: 7, user: { login: 'mallory' }, body: marker, created_at: '2026-01-01T00:00:00Z' }],
  });
  assert.equal(forged.core.outputs.already_reviewed, 'false');
  const legacy = await resolve('pull_request', pr, {
    commentsFor: () => [
      {
        id: 3,
        user: { login: 'github-actions[bot]' },
        body: '<!-- cursor-dependabot-review -->\n## old',
        created_at: '2026-01-01T00:00:00Z',
      },
    ],
  });
  assert.equal(legacy.core.outputs.already_reviewed, 'false');
});

test('Renovate and workflow_dispatch still review when a marker exists', async () => {
  const marker = reviewMarkerForUpgrade('Bump lodash from 1.0.0 to 4.17.21', singleBody('abc1234'));
  const renovate = {
    number: 7,
    title: 'Update dependency lodash to v4.17.21',
    body: 'https://github.com/lodash/lodash',
    user: { login: 'renovate[bot]' },
    head: { sha: 'reno' },
  };
  const reno = await resolve('pull_request', renovate, { commentsFor: () => [botComment(marker)] });
  assert.equal(reno.core.outputs.already_reviewed, 'false');
  assert.equal(reno.core.outputs.review_marker, '');
  assert.equal(
    reno.github.calls.some((call) => call[0] === 'listComments'),
    false,
  );

  const title = 'Bump lodash from 4.17.20 to 4.17.21';
  const pr = {
    number: 42,
    title,
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const dispatched = await resolve('workflow_dispatch', pr, {
    commentsFor: () => [botComment(reviewMarkerForUpgrade(title, pr.body))],
    inputs: { pr_number: '42' },
  });
  assert.equal(dispatched.core.outputs.already_reviewed, 'false');
  assert.equal(dispatched.core.outputs.review_marker, reviewMarkerForUpgrade(title, pr.body));
  assert.equal(
    dispatched.github.calls.some((call) => call[0] === 'listComments'),
    false,
  );
});

test('comment listing failure runs the review instead of skipping it', async () => {
  const pr = {
    number: 42,
    title: 'Bump lodash from 4.17.20 to 4.17.21',
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const { core } = await resolve('pull_request', pr, { listError: new Error('rate limit') });
  assert.equal(core.outputs.already_reviewed, 'false');
  assert.equal(core.failed, '');
  assert.match(core.warnings.join('\n'), /rate limit/);
});

test('only a complete analysis stamps the upgrade marker', () => {
  const marker = reviewMarkerForUpgrade('Bump lodash from 4.17.20 to 4.17.21', singleBody('abc1234'));
  assert.equal(postComment.selectPostedMarker(marker, '{"result":"Verdict: benign","complete":true}'), marker);
  assert.equal(
    postComment.selectPostedMarker(marker, '{"result":"CURSOR_API_KEY is not set; analysis was skipped."}'),
    context.LEGACY_REVIEW_MARKER,
  );
  assert.equal(postComment.selectPostedMarker('', '{"complete":true}'), context.LEGACY_REVIEW_MARKER);
});

test('completed analysis updates an Actions bot marker and treats a human quote as commentary', async () => {
  const marker = reviewMarkerForUpgrade('Bump lodash from 4.17.20 to 4.17.21', singleBody('abc1234'));
  await withWorkspace(async (directory) => {
    process.env.REVIEW_MARKER = marker;
    process.env.PR_NUMBER = '42';
    fs.writeFileSync(path.join(directory, 'cursor_output.json'), '{"result":"Verdict: benign","complete":true}\n');
    const quiet = fakeGithub({
      commentsFor: () => [
        {
          id: 11,
          user: { login: 'github-actions[bot]' },
          body: '<!-- cursor-dependabot-review -->\n## previous',
          created_at: '2026-01-01T00:00:00Z',
        },
      ],
    });
    await postComment({ github: quiet, context: { repo: { owner: 'acme', repo: 'widgets' } }, core: fakeCore() });
    const update = quiet.calls.find((call) => call[0] === 'updateComment');
    assert.equal(update[1].comment_id, 11);
    assert.equal(update[1].body.startsWith(marker), true);

    const quoted = fakeGithub({
      commentsFor: () => [
        {
          id: 11,
          user: { login: 'github-actions[bot]' },
          body: '<!-- cursor-dependabot-review -->\n## previous',
          created_at: '2026-01-01T00:00:00Z',
        },
        { id: 12, user: { login: 'mallory' }, body: marker, created_at: '2026-01-02T00:00:00Z' },
      ],
    });
    await postComment({ github: quoted, context: { repo: { owner: 'acme', repo: 'widgets' } }, core: fakeCore() });
    assert.equal(
      quoted.calls.some((call) => call[0] === 'updateComment'),
      false,
    );
    const created = quoted.calls.find((call) => call[0] === 'createComment');
    assert.equal(created[1].body.startsWith(marker), true);
  });
});
