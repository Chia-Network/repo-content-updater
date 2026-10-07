'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const context = require('./dependency-cursor-review-dependabot-context.js');
const { run, MAX_PR_COMMITS } = require('./dependency-cursor-review-target-pr.js');
const postComment = require('./dependency-cursor-review-post-comment.js');

const { parseDependencyUpdate, reviewMarkerFromCommitMessages } = context;

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

function yamlScalar(value) {
  return /^[A-Za-z0-9./][A-Za-z0-9._+\-/:]*$/.test(value) ? value : JSON.stringify(value);
}

function commitMessage(entries) {
  const lines = ['updated-dependencies:'];
  for (const entry of entries) {
    const keys = [
      'dependency-name',
      'dependency-version',
      'dependency-type',
      'update-type',
      'dependency-group',
      'directory',
    ];
    let first = true;
    for (const key of keys) {
      if (entry[key] == null || entry[key] === '') continue;
      lines.push(`${first ? '- ' : '  '}${key}: ${yamlScalar(entry[key])}`);
      first = false;
    }
  }
  return ['Bump', '', '---', ...lines, '...', ''].join('\n');
}

function markerFor(entries) {
  return reviewMarkerFromCommitMessages([commitMessage(entries)]);
}

function lodash(version) {
  return [
    {
      'dependency-name': 'lodash',
      'dependency-version': version,
      'dependency-type': 'direct:production',
      'update-type': 'version-update:semver-patch',
    },
  ];
}

function dependabotCommit(message, { login = 'dependabot[bot]', verified = true } = {}) {
  return {
    sha: 'abc',
    author: login ? { login } : null,
    commit: { message, verification: { verified } },
  };
}

function verifiedCommits(...entryLists) {
  return entryLists.map((entries) => dependabotCommit(commitMessage(entries)));
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

function fakeGithub({ pr, commentsFor = () => [], listError, commits = [], commitListError }) {
  const calls = [];
  const api = {
    calls,
    rest: {
      pulls: {
        async get(params) {
          calls.push(['pulls.get', params]);
          return { data: pr };
        },
        async listCommits(params) {
          calls.push(['listCommits', params]);
          if (commitListError) throw commitListError;
          return { data: commits.slice(0, 30) };
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
      calls.push(['paginate', fn, params]);
      if (fn === api.rest.pulls.listCommits) {
        if (commitListError) throw commitListError;
        return commits;
      }
      return fn(params);
    },
  };
  return api;
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

test('a commit trailer keeps the version and ignores group or directory title suffixes', async () => {
  const entries = [
    {
      'dependency-name': 'business',
      'dependency-version': '1.5.0',
      'dependency-type': 'direct:production',
      'dependency-group': 'go_modules',
    },
  ];
  const pr = {
    number: 42,
    title: 'Bump business from 1.4.0 to 1.5.0 in the go_modules group across 1 directory',
    body: 'Updates `business` from 1.4.0 to 1.5.0\n\nBump business from 1.4.0 to 1.5.0 in /directory in the all-the-things group',
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const { core } = await resolve('pull_request', pr, { commits: verifiedCommits(entries), commentsFor: () => [] });
  assert.equal(payloadOf(core.outputs.review_marker), 'business\t1.5.0');
  assert.equal(payloadOf(core.outputs.review_marker).includes('across'), false);
  assert.equal(payloadOf(core.outputs.review_marker).includes('in /directory'), false);
  assert.notEqual(core.outputs.review_marker, markerFor([{ ...entries[0], 'dependency-version': '1.6.0' }]));
});

test('a requirement trailer keeps the operator version whole', () => {
  const older = markerFor([
    { 'dependency-name': 'business', 'dependency-version': '~> 1.5.0', 'dependency-type': 'direct:production' },
  ]);
  const newer = markerFor([
    { 'dependency-name': 'business', 'dependency-version': '~> 1.6.0', 'dependency-type': 'direct:production' },
  ]);
  assert.equal(payloadOf(older), 'business\t~> 1.5.0');
  assert.equal(payloadOf(newer), 'business\t~> 1.6.0');
  assert.notEqual(older, newer);
});

test('a grouped trailer includes every dependency and changes when one version changes', () => {
  const group = [
    { 'dependency-name': 'minimatch', 'dependency-version': '9.0.5', 'dependency-group': 'npm_and_yarn' },
    { 'dependency-name': 'brace-expansion', 'dependency-version': '2.0.2', 'dependency-group': 'npm_and_yarn' },
  ];
  const marker = markerFor(group);
  assert.equal(marker, markerFor([...group].reverse()));
  const payload = payloadOf(marker);
  assert.match(payload, /^brace-expansion\t2\.0\.2\nminimatch\t9\.0\.5$/);
  const changed = markerFor([
    { 'dependency-name': 'minimatch', 'dependency-version': '9.0.6', 'dependency-group': 'npm_and_yarn' },
    { 'dependency-name': 'brace-expansion', 'dependency-version': '2.0.2', 'dependency-group': 'npm_and_yarn' },
  ]);
  assert.notEqual(marker, changed);
});

test('a directory field is kept and a missing directory is not guessed', () => {
  const withDirectory = markerFor([
    { 'dependency-name': 'business', 'dependency-version': '1.5.0', directory: '/services' },
    { 'dependency-name': 'business', 'dependency-version': '1.5.0', directory: '/tools' },
  ]);
  const payload = payloadOf(withDirectory);
  assert.match(payload, /business\t1\.5\.0\t\/services/);
  assert.match(payload, /business\t1\.5\.0\t\/tools/);
  const shared = markerFor([{ 'dependency-name': 'business', 'dependency-version': '1.5.0' }]);
  assert.equal(payloadOf(shared), 'business\t1.5.0');
  assert.equal(shared, markerFor([{ 'dependency-name': 'business', 'dependency-version': '1.5.0' }]));
});

test('the union of every commit trailer is the identity', () => {
  const marker = reviewMarkerFromCommitMessages([
    commitMessage(lodash('4.17.21')),
    commitMessage([{ 'dependency-name': 'minimatch', 'dependency-version': '9.0.5' }]),
    commitMessage(lodash('4.17.21')),
  ]);
  assert.equal(payloadOf(marker), 'lodash\t4.17.21\nminimatch\t9.0.5');
  assert.equal(
    reviewMarkerFromCommitMessages([commitMessage(lodash('4.17.21')), commitMessage(lodash('4.17.22'))]),
    reviewMarkerFromCommitMessages([commitMessage(lodash('4.17.22')), commitMessage(lodash('4.17.21'))]),
  );
});

test('malformed or missing commit metadata does not build a marker', () => {
  assert.equal(reviewMarkerFromCommitMessages([]), '');
  assert.equal(reviewMarkerFromCommitMessages(['Bump lodash from 4.17.20 to 4.17.21\n']), '');
  assert.equal(reviewMarkerFromCommitMessages(['---\nupdated-dependencies:\n...']), '');
  assert.equal(reviewMarkerFromCommitMessages(['---\nupdated-dependencies:\n- dependency-name: lodash\n...']), '');
  assert.equal(
    reviewMarkerFromCommitMessages([
      '---\nupdated-dependencies:\n- dependency-name: lodash\n  dependency-version: ~> 1.5.0\n...',
    ]),
    '',
  );
  assert.equal(reviewMarkerFromCommitMessages([commitMessage(lodash('4.17.21')), 'no trailer here\n']), '');
  assert.equal(
    markerFor([
      { 'dependency-name': 'minimist', 'dependency-version': '1.2.6' },
      { 'dependency-name': 'business', 'dependency-version': '' },
    ]),
    '',
  );
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
  const marker = markerFor(lodash('4.17.21'));
  const pr = {
    number: 42,
    title,
    body: singleBody('bbbbbbbbbbb'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'newheadsha' },
  };
  const { core, github } = await resolve('pull_request', pr, {
    commits: verifiedCommits(lodash('4.17.21')),
    commentsFor: () => [botComment(marker)],
  });
  assert.equal(core.outputs.already_reviewed, 'true');
  assert.equal(core.outputs.review_marker, marker);
  assert.equal(core.outputs.head_sha, 'newheadsha');
  assert.equal(github.calls.find((call) => call[0] === 'listComments')[1].issue_number, 42);
});

test('a new pull request is reviewed even for a version reviewed elsewhere', async () => {
  const previous = markerFor(lodash('4.17.21'));
  const pr = {
    number: 99,
    title: 'Bump lodash from 4.17.20 to 4.17.22',
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const { core } = await resolve('pull_request', pr, {
    commits: verifiedCommits(lodash('4.17.22')),
    commentsFor: (number) => (number === 42 ? [botComment(previous)] : []),
  });
  assert.equal(core.outputs.already_reviewed, 'false');
});

test('same pull request with a new target version is reviewed again', async () => {
  const oldMarker = markerFor(lodash('4.17.21'));
  const pr = {
    number: 42,
    title: 'Bump lodash from 4.17.20 to 4.17.22',
    body: singleBody('def5678'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head2' },
  };
  const { core } = await resolve('pull_request', pr, {
    commits: verifiedCommits(lodash('4.17.22')),
    commentsFor: () => [botComment(oldMarker)],
  });
  assert.equal(core.outputs.already_reviewed, 'false');
});

test('a marker quoted after the first line does not suppress the review', async () => {
  const title = 'Bump lodash from 4.17.20 to 4.17.22';
  const marker = markerFor(lodash('4.17.22'));
  const older = markerFor(lodash('4.17.21'));
  const pr = {
    number: 42,
    title,
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const { core } = await resolve('pull_request', pr, {
    commits: verifiedCommits(lodash('4.17.22')),
    commentsFor: () => [
      {
        id: 8,
        user: { login: 'github-actions[bot]' },
        body: `${older}\n## analysis\nRelease notes quote ${marker}\n`,
        created_at: '2026-01-01T00:00:00Z',
      },
    ],
  });
  assert.equal(core.outputs.already_reviewed, 'false');
});

test('a forged marker or a legacy marker does not suppress the review', async () => {
  const title = 'Bump lodash from 4.17.20 to 4.17.21';
  const marker = markerFor(lodash('4.17.21'));
  const pr = {
    number: 42,
    title,
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const forged = await resolve('pull_request', pr, {
    commits: verifiedCommits(lodash('4.17.21')),
    commentsFor: () => [{ id: 7, user: { login: 'mallory' }, body: marker, created_at: '2026-01-01T00:00:00Z' }],
  });
  assert.equal(forged.core.outputs.already_reviewed, 'false');
  const legacy = await resolve('pull_request', pr, {
    commits: verifiedCommits(lodash('4.17.21')),
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
  const marker = markerFor(lodash('4.17.21'));
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
    commits: verifiedCommits(lodash('4.17.21')),
    commentsFor: () => [botComment(marker)],
    inputs: { pr_number: '42' },
  });
  assert.equal(dispatched.core.outputs.already_reviewed, 'false');
  assert.equal(dispatched.core.outputs.review_marker, marker);
  assert.equal(
    dispatched.github.calls.some((call) => call[0] === 'listComments'),
    false,
  );
});

test('a second non-Dependabot commit or an unverified commit fails open', async () => {
  const pr = {
    number: 42,
    title: 'Bump lodash from 4.17.20 to 4.17.21',
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const good = dependabotCommit(commitMessage(lodash('4.17.21')));
  const human = dependabotCommit(commitMessage([{ 'dependency-name': 'left-pad', 'dependency-version': '1.0.0' }]), {
    login: 'maintainer',
  });
  const unverified = dependabotCommit(commitMessage(lodash('4.17.21')), { verified: false });
  for (const commits of [
    [good, human],
    [good, unverified],
    [dependabotCommit(commitMessage(lodash('4.17.21')), { login: '' })],
  ]) {
    const { core } = await resolve('pull_request', pr, { commits, commentsFor: () => [] });
    assert.equal(core.outputs.review_marker, '');
    assert.equal(core.outputs.already_reviewed, 'false');
  }
});

test('more than 30 commits are read through paginate', async () => {
  const commits = [];
  for (let index = 0; index < 31; index += 1) {
    commits.push(
      dependabotCommit(
        commitMessage([{ 'dependency-name': `pkg-${String(index).padStart(2, '0')}`, 'dependency-version': '1.0.0' }]),
      ),
    );
  }
  const pr = {
    number: 42,
    title: 'Bump the group',
    body: 'https://github.com/example/pkg',
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const { core, github } = await resolve('pull_request', pr, { commits, commentsFor: () => [] });
  assert.equal(
    github.calls.some((call) => call[0] === 'paginate' && call[1] === github.rest.pulls.listCommits),
    true,
  );
  assert.match(payloadOf(core.outputs.review_marker), /pkg-30\t1\.0\.0/);
  assert.equal(core.outputs.already_reviewed, 'false');
});

test('an empty commit list, an API error, or too many commits fails open', async () => {
  const pr = {
    number: 42,
    title: 'Bump lodash from 4.17.20 to 4.17.21',
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const empty = await resolve('pull_request', pr, { commits: [], commentsFor: () => [] });
  assert.equal(empty.core.outputs.review_marker, '');
  assert.equal(empty.core.outputs.already_reviewed, 'false');

  const failed = await resolve('pull_request', pr, {
    commitListError: new Error('rate limit'),
    commentsFor: () => [],
  });
  assert.equal(failed.core.outputs.review_marker, '');
  assert.equal(failed.core.outputs.already_reviewed, 'false');
  assert.match(failed.core.warnings.join('\n'), /rate limit/);

  const tooMany = Array.from({ length: MAX_PR_COMMITS + 1 }, () => dependabotCommit(commitMessage(lodash('4.17.21'))));
  const bounded = await resolve('pull_request', pr, { commits: tooMany, commentsFor: () => [] });
  assert.equal(bounded.core.outputs.review_marker, '');
  assert.equal(bounded.core.outputs.already_reviewed, 'false');
});

test('comment listing failure runs the review instead of skipping it', async () => {
  const pr = {
    number: 42,
    title: 'Bump lodash from 4.17.20 to 4.17.21',
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
  const { core } = await resolve('pull_request', pr, {
    commits: verifiedCommits(lodash('4.17.21')),
    listError: new Error('rate limit'),
  });
  assert.equal(core.outputs.already_reviewed, 'false');
  assert.equal(core.failed, '');
  assert.match(core.warnings.join('\n'), /rate limit/);
});

test('only a complete analysis stamps the upgrade marker', () => {
  const marker = markerFor(lodash('4.17.21'));
  assert.equal(postComment.selectPostedMarker(marker, '{"result":"Verdict: benign","complete":true}'), marker);
  assert.equal(
    postComment.selectPostedMarker(marker, '{"result":"CURSOR_API_KEY is not set; analysis was skipped."}'),
    context.LEGACY_REVIEW_MARKER,
  );
  assert.equal(postComment.selectPostedMarker('', '{"complete":true}'), context.LEGACY_REVIEW_MARKER);
});

test('completed analysis updates an Actions bot marker and treats a human quote as commentary', async () => {
  const marker = markerFor(lodash('4.17.21'));
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

    const unrelated = fakeGithub({
      commentsFor: () => [
        {
          id: 21,
          user: { login: 'github-actions[bot]' },
          body: `Coverage report\n<!-- cursor-dependabot-review quoted in the body`,
          created_at: '2026-01-03T00:00:00Z',
        },
      ],
    });
    await postComment({ github: unrelated, context: { repo: { owner: 'acme', repo: 'widgets' } }, core: fakeCore() });
    assert.equal(
      unrelated.calls.some((call) => call[0] === 'updateComment'),
      false,
    );
    const added = unrelated.calls.find((call) => call[0] === 'createComment');
    assert.equal(added[1].issue_number, 42);
    assert.equal(added[1].body.startsWith(marker), true);
  });
});
