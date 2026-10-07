'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const context = require('./dependency-cursor-review-dependabot-context.js');
const { run } = require('./dependency-cursor-review-target-pr.js');
const postComment = require('./dependency-cursor-review-post-comment.js');

const { commentMatchesIdentity, parseDependencyUpdate, reviewMarkerForIdentity, upgradeIdentity } = context;

function fakeCore() {
  return {
    outputs: {},
    failed: '',
    notices: [],
    warnings: [],
    infos: [],
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
    info(message) {
      this.infos.push(message);
    },
  };
}

function singleBody(sha) {
  return [
    'Bumps [lodash](https://github.com/lodash/lodash) from 4.17.20 to 4.17.21.',
    '<details>',
    '<summary>Release notes</summary>',
    'Ships a small patch.',
    '</details>',
    '<details>',
    '<summary>Commits</summary>',
    `<li>${sha} fix something</li>`,
    '</details>',
  ].join('\n');
}

function groupBody(sha, bumps) {
  const sections = bumps.map(([name, from, to]) =>
    [`Updates \`${name}\` from ${from} to ${to}`, '<details>', '<summary>Commits</summary>', sha, '</details>'].join(
      '\n',
    ),
  );
  return `Bumps the npm_and_yarn group with ${bumps.length} updates.\n\n${sections.join('\n\n')}`;
}

function botComment(identity) {
  return {
    id: 1,
    user: { login: 'github-actions[bot]' },
    body: `${reviewMarkerForIdentity(identity)}\n## review`,
    created_at: '2026-01-01T00:00:00Z',
  };
}

function fakeGithub({ pr, commentsFor, listError }) {
  const calls = [];
  const github = {
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
  return github;
}

async function resolve(eventName, pr, { commentsFor, listError, inputs } = {}) {
  const core = fakeCore();
  const github = fakeGithub({
    pr,
    commentsFor: commentsFor || (() => []),
    listError,
  });
  const contextPayload =
    eventName === 'pull_request'
      ? { eventName, repo: { owner: 'acme', repo: 'widgets' }, payload: { pull_request: pr } }
      : {
          eventName,
          repo: { owner: 'acme', repo: 'widgets' },
          payload: { inputs: inputs || { pr_number: String(pr.number) } },
        };
  await run({ github, context: contextPayload, core });
  return { core, github };
}

test('single-dependency identity ignores rebase SHAs and from-version', () => {
  const titleA = 'Bump lodash from 4.17.20 to 4.17.21';
  const titleB = 'Bump lodash from 4.17.19 to 4.17.21';
  const idA = upgradeIdentity(titleA, singleBody('aaaaaaaaaaa'));
  const idB = upgradeIdentity(titleB, singleBody('bbbbbbbbbbb'));
  assert.equal(idA, idB);
  assert.equal(idA.includes('aaaaaaaaaaa'), false);
  assert.equal(idA.includes('4.17.20'), false);
  assert.equal(idA.includes('4.17.21'), true);
});

test('a new target version is a different upgrade', () => {
  const current = upgradeIdentity('Bump lodash from 4.17.20 to 4.17.21', singleBody('abc1234'));
  const next = upgradeIdentity('Bump lodash from 4.17.20 to 4.17.22', singleBody('abc1234'));
  assert.notEqual(current, next);
});

test('group identity ignores commit SHAs inside release details', () => {
  const bumps = [
    ['brace-expansion', '2.0.1', '2.0.2'],
    ['minimatch', '9.0.3', '9.0.5'],
  ];
  const title = 'Bump the npm_and_yarn group with 2 updates';
  const first = upgradeIdentity(title, groupBody('1111111', bumps));
  const rebase = upgradeIdentity(title, groupBody('2222222', bumps));
  assert.equal(first, rebase);
  assert.equal(first.includes('1111111'), false);
  const changed = upgradeIdentity(
    title,
    groupBody('1111111', [
      ['brace-expansion', '2.0.1', '2.0.2'],
      ['minimatch', '9.0.3', '9.0.6'],
    ]),
  );
  assert.notEqual(first, changed);
});

test('multiple explicit updates beat a title that names only one package', () => {
  const body = [
    'Bumps [lodash](https://github.com/lodash/lodash) from 4.17.20 to 4.17.21.',
    '',
    'Updates `lodash` from 4.17.20 to 4.17.21',
    'Updates `semver` from 7.5.0 to 7.6.0',
  ].join('\n');
  const identity = upgradeIdentity('Bump lodash from 4.17.20 to 4.17.21', body);
  assert.match(identity, /lodash/);
  assert.match(identity, /semver/);
  assert.match(identity, /7\.6\.0/);
});

test('table bumps are used when the title has no single target version', () => {
  const body = [
    'Bumps the npm group with 2 updates.',
    '',
    '| Package | From | To |',
    '| --- | --- | --- |',
    '| left-pad | 1.0.0 | 1.1.0 |',
    '| semver | 7.5.0 | 7.6.0 |',
  ].join('\n');
  const identity = upgradeIdentity('Bump the npm group with 2 updates', body);
  assert.match(identity, /left-pad/);
  assert.match(identity, /1\.1\.0/);
  assert.match(identity, /semver/);
  assert.equal(identity.includes('1.0.0'), false);
});

test('parseDependencyUpdate still extracts upstream notes and commits', () => {
  const parsed = parseDependencyUpdate('Bump lodash from 4.17.20 to 4.17.21', singleBody('deadbee'));
  assert.equal(parsed.upstreamRepo, 'lodash/lodash');
  assert.equal(parsed.packageName, 'lodash');
  assert.equal(parsed.fromVersion, '4.17.20');
  assert.equal(parsed.toVersion, '4.17.21');
  assert.match(parsed.releaseNotes, /small patch/);
  assert.match(parsed.commits, /deadbee/);
});

test('context JSON stays limited to the prompt fields', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'dcr-context-'));
  const previous = process.cwd();
  const previousEnv = {
    PR_TITLE: process.env.PR_TITLE,
    PR_BODY: process.env.PR_BODY,
    PR_NUMBER: process.env.PR_NUMBER,
  };
  process.chdir(directory);
  process.env.PR_TITLE = 'Bump lodash from 4.17.20 to 4.17.21';
  process.env.PR_BODY = singleBody('abc1234');
  process.env.PR_NUMBER = '42';
  try {
    const core = fakeCore();
    await context({ github: {}, context: {}, core });
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
    assert.equal(core.outputs.package_name, 'lodash');
    assert.equal(core.outputs.to_version, '4.17.21');
    assert.equal(core.failed, '');
  } finally {
    process.chdir(previous);
    for (const [key, value] of Object.entries(previousEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('rebase of the same Dependabot upgrade does not review again', async () => {
  const title = 'Bump lodash from 4.17.20 to 4.17.21';
  const identity = upgradeIdentity(title, singleBody('aaaaaaaaaaa'));
  const pr = {
    number: 42,
    title,
    body: singleBody('bbbbbbbbbbb'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'newheadsha' },
  };
  const { core, github } = await resolve('pull_request', pr, {
    commentsFor: () => [botComment(identity)],
  });
  assert.equal(core.outputs.already_reviewed, 'true');
  assert.equal(core.outputs.head_sha, 'newheadsha');
  assert.equal(core.failed, '');
  assert.equal(
    github.calls.some((call) => call[0] === 'listComments'),
    true,
  );
  const listed = github.calls.find((call) => call[0] === 'listComments');
  assert.equal(listed[1].issue_number, 42);
});

test('a new pull request is reviewed even for a version reviewed elsewhere', async () => {
  const title = 'Bump lodash from 4.17.20 to 4.17.22';
  const previousIdentity = upgradeIdentity('Bump lodash from 4.17.20 to 4.17.21', singleBody('abc1234'));
  const pr = {
    number: 99,
    title,
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const { core } = await resolve('pull_request', pr, {
    commentsFor: (number) => (number === 42 ? [botComment(previousIdentity)] : []),
  });
  assert.equal(core.outputs.already_reviewed, 'false');
});

test('same pull request with a new target version is reviewed again', async () => {
  const oldIdentity = upgradeIdentity('Bump lodash from 4.17.20 to 4.17.21', singleBody('abc1234'));
  const title = 'Bump lodash from 4.17.20 to 4.17.22';
  const pr = {
    number: 42,
    title,
    body: singleBody('def5678'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head2' },
  };
  const { core } = await resolve('pull_request', pr, {
    commentsFor: () => [botComment(oldIdentity)],
  });
  assert.equal(core.outputs.already_reviewed, 'false');
});

test('a forged marker from another user does not suppress the review', async () => {
  const title = 'Bump lodash from 4.17.20 to 4.17.21';
  const identity = upgradeIdentity(title, singleBody('abc1234'));
  const pr = {
    number: 42,
    title,
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const { core } = await resolve('pull_request', pr, {
    commentsFor: () => [
      {
        id: 7,
        user: { login: 'mallory' },
        body: reviewMarkerForIdentity(identity),
        created_at: '2026-01-01T00:00:00Z',
      },
    ],
  });
  assert.equal(core.outputs.already_reviewed, 'false');
});

test('legacy marker without a version does not suppress a later push', async () => {
  const title = 'Bump lodash from 4.17.20 to 4.17.21';
  const pr = {
    number: 42,
    title,
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const { core } = await resolve('pull_request', pr, {
    commentsFor: () => [
      {
        id: 3,
        user: { login: 'github-actions[bot]' },
        body: '<!-- cursor-dependabot-review -->\n## old',
        created_at: '2026-01-01T00:00:00Z',
      },
    ],
  });
  assert.equal(core.outputs.already_reviewed, 'false');
});

test('Renovate pulls still review on every synchronize', async () => {
  const pr = {
    number: 7,
    title: 'Update dependency lodash to v4.17.21',
    body: 'https://github.com/lodash/lodash',
    user: { login: 'renovate[bot]' },
    head: { sha: 'reno' },
  };
  const identity = upgradeIdentity('Bump lodash from 1.0.0 to 4.17.21', singleBody('abc1234'));
  const { core, github } = await resolve('pull_request', pr, {
    commentsFor: () => [botComment(identity)],
  });
  assert.equal(core.outputs.already_reviewed, 'false');
  assert.equal(core.outputs.upgrade_identity, '');
  assert.equal(
    github.calls.some((call) => call[0] === 'listComments'),
    false,
  );
});

test('workflow_dispatch still reviews a Dependabot PR that already has a marker', async () => {
  const title = 'Bump lodash from 4.17.20 to 4.17.21';
  const identity = upgradeIdentity(title, singleBody('abc1234'));
  const pr = {
    number: 42,
    title,
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const { core, github } = await resolve('workflow_dispatch', pr, {
    commentsFor: () => [botComment(identity)],
    inputs: { pr_number: '42' },
  });
  assert.equal(core.outputs.already_reviewed, 'false');
  assert.equal(core.failed, '');
  assert.equal(
    github.calls.some((call) => call[0] === 'listComments'),
    false,
  );
  assert.equal(postComment.decodeUpgradeIdentity(core.outputs.upgrade_identity), identity);
});

test('comment listing failure runs the review instead of skipping it', async () => {
  const title = 'Bump lodash from 4.17.20 to 4.17.21';
  const pr = {
    number: 42,
    title,
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const { core } = await resolve('pull_request', pr, {
    listError: new Error('rate limit'),
  });
  assert.equal(core.outputs.already_reviewed, 'false');
  assert.equal(core.failed, '');
  assert.match(core.warnings.join('\n'), /rate limit/);
});

test('marker round trip matches only the reviewed upgrade', () => {
  const identity = upgradeIdentity('Bump lodash from 4.17.20 to 4.17.21', singleBody('abc1234'));
  const encoded = Buffer.from(identity, 'utf8').toString('base64');
  assert.equal(encoded.includes('\n'), false);
  const decoded = postComment.decodeUpgradeIdentity(encoded);
  const marker = postComment.selectPostedMarker(decoded, '{"result":"Verdict: benign"}');
  assert.equal(commentMatchesIdentity(marker, identity), true);
  assert.equal(commentMatchesIdentity(marker, upgradeIdentity('Bump lodash from 4.17.20 to 9.9.9', '')), false);
  const skipped = postComment.selectPostedMarker(
    decoded,
    '{"result":"CURSOR_API_KEY is not set; analysis was skipped."}',
  );
  assert.equal(skipped, context.LEGACY_REVIEW_MARKER);
  assert.equal(commentMatchesIdentity(skipped, identity), false);
});

test('completed analysis updates an existing marker comment in place', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'dcr-post-'));
  const previous = process.cwd();
  const previousIdentity = process.env.UPGRADE_IDENTITY;
  const previousNumber = process.env.PR_NUMBER;
  const identity = upgradeIdentity('Bump lodash from 4.17.20 to 4.17.21', singleBody('abc1234'));
  process.chdir(directory);
  process.env.UPGRADE_IDENTITY = Buffer.from(identity, 'utf8').toString('base64');
  process.env.PR_NUMBER = '42';
  fs.writeFileSync(path.join(directory, 'cursor_output.json'), '{"result":"Verdict: benign"}\n');
  const github = fakeGithub({
    pr: {},
    commentsFor: () => [
      {
        id: 11,
        user: { login: 'github-actions[bot]' },
        body: '<!-- cursor-dependabot-review -->\n## previous',
        created_at: '2026-01-01T00:00:00Z',
      },
    ],
  });
  try {
    await postComment({
      github,
      context: { repo: { owner: 'acme', repo: 'widgets' } },
      core: fakeCore(),
    });
    const update = github.calls.find((call) => call[0] === 'updateComment');
    assert.ok(update);
    assert.equal(update[1].comment_id, 11);
    assert.equal(update[1].body.startsWith(reviewMarkerForIdentity(identity)), true);
    assert.equal(
      github.calls.some((call) => call[0] === 'createComment'),
      false,
    );
  } finally {
    process.chdir(previous);
    if (previousIdentity === undefined) delete process.env.UPGRADE_IDENTITY;
    else process.env.UPGRADE_IDENTITY = previousIdentity;
    if (previousNumber === undefined) delete process.env.PR_NUMBER;
    else process.env.PR_NUMBER = previousNumber;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('a quoted marker in a later human comment is not overwritten', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'dcr-post-human-'));
  const previous = process.cwd();
  const previousIdentity = process.env.UPGRADE_IDENTITY;
  const previousNumber = process.env.PR_NUMBER;
  const identity = upgradeIdentity('Bump lodash from 4.17.20 to 4.17.21', singleBody('abc1234'));
  process.chdir(directory);
  process.env.UPGRADE_IDENTITY = Buffer.from(identity, 'utf8').toString('base64');
  process.env.PR_NUMBER = '42';
  fs.writeFileSync(path.join(directory, 'cursor_output.json'), '{"result":"Verdict: benign"}\n');
  const github = fakeGithub({
    pr: {},
    commentsFor: () => [
      {
        id: 11,
        user: { login: 'github-actions[bot]' },
        body: '<!-- cursor-dependabot-review -->\n## previous',
        created_at: '2026-01-01T00:00:00Z',
      },
      {
        id: 12,
        user: { login: 'mallory' },
        body: reviewMarkerForIdentity(identity),
        created_at: '2026-01-02T00:00:00Z',
      },
    ],
  });
  try {
    await postComment({
      github,
      context: { repo: { owner: 'acme', repo: 'widgets' } },
      core: fakeCore(),
    });
    const update = github.calls.find((call) => call[0] === 'updateComment');
    assert.ok(update);
    assert.equal(update[1].comment_id, 11);
    assert.equal(
      github.calls.some((call) => call[0] === 'createComment'),
      false,
    );
  } finally {
    process.chdir(previous);
    if (previousIdentity === undefined) delete process.env.UPGRADE_IDENTITY;
    else process.env.UPGRADE_IDENTITY = previousIdentity;
    if (previousNumber === undefined) delete process.env.PR_NUMBER;
    else process.env.PR_NUMBER = previousNumber;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
