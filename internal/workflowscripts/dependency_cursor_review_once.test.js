'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const context = require('./dependency-cursor-review-dependabot-context.js');
const { run } = require('./dependency-cursor-review-target-pr.js');
const postComment = require('./dependency-cursor-review-post-comment.js');

const { parseDependencyUpdate, reviewMarkerFromMetadata } = context;

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

function metadata(dependencies) {
  return JSON.stringify(dependencies);
}

function markerFor(dependencies) {
  return reviewMarkerFromMetadata(metadata(dependencies));
}

function lodash(version) {
  return [{ dependencyName: 'lodash', newVersion: version, directory: '/' }];
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
  const previous = process.env.UPDATED_DEPENDENCIES_JSON;
  if (Object.prototype.hasOwnProperty.call(options, 'metadata')) {
    process.env.UPDATED_DEPENDENCIES_JSON = options.metadata;
  } else {
    delete process.env.UPDATED_DEPENDENCIES_JSON;
  }
  const core = fakeCore();
  const github = fakeGithub({ pr, ...options });
  const payload =
    eventName === 'pull_request'
      ? { pull_request: pr }
      : { inputs: options.inputs || { pr_number: String(pr.number) } };
  try {
    await run({
      github,
      context: { eventName, repo: { owner: 'acme', repo: 'widgets' }, payload },
      core,
    });
  } finally {
    if (previous === undefined) delete process.env.UPDATED_DEPENDENCIES_JSON;
    else process.env.UPDATED_DEPENDENCIES_JSON = previous;
  }
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

test('structured metadata keeps the version and ignores a group or directory title suffix', () => {
  const older = markerFor([
    { dependencyName: 'business', newVersion: '1.5.0', directory: '/', dependencyGroup: 'go_modules' },
  ]);
  const newer = markerFor([
    { dependencyName: 'business', newVersion: '1.6.0', directory: '/', dependencyGroup: 'go_modules' },
  ]);
  assert.equal(payloadOf(older), 'business\t1.5.0\t/');
  assert.equal(payloadOf(newer), 'business\t1.6.0\t/');
  assert.notEqual(older, newer);
  assert.equal(payloadOf(older).includes('across'), false);
  assert.equal(payloadOf(older).includes('in /directory'), false);
});

test('a requirement update uses the structured new version, not a truncated operator', () => {
  const older = markerFor([{ dependencyName: 'business', newVersion: '~> 1.5.0', directory: '/' }]);
  const newer = markerFor([{ dependencyName: 'business', newVersion: '~> 1.6.0', directory: '/' }]);
  assert.equal(payloadOf(older), 'business\t~> 1.5.0\t/');
  assert.equal(payloadOf(newer), 'business\t~> 1.6.0\t/');
  assert.notEqual(older, newer);
});

test('grouped metadata includes every dependency and changes when one version changes', () => {
  const group = [
    { dependencyName: 'minimatch', newVersion: '9.0.5', directory: '/' },
    { dependencyName: 'brace-expansion', newVersion: '2.0.2', directory: '/' },
  ];
  const marker = markerFor(group);
  assert.equal(marker, markerFor([...group].reverse()));
  const payload = payloadOf(marker);
  assert.match(payload, /brace-expansion\t2\.0\.2\t\//);
  assert.match(payload, /minimatch\t9\.0\.5\t\//);
  const changed = markerFor([
    { dependencyName: 'minimatch', newVersion: '9.0.6', directory: '/' },
    { dependencyName: 'brace-expansion', newVersion: '2.0.2', directory: '/' },
  ]);
  assert.notEqual(marker, changed);
});

test('multi-directory metadata keeps directories distinct', () => {
  const deps = [
    { dependencyName: 'business', newVersion: '1.5.0', directory: '/tools' },
    { dependencyName: 'business', newVersion: '1.5.0', directory: '/services' },
  ];
  const marker = markerFor(deps);
  const payload = payloadOf(marker);
  assert.match(payload, /business\t1\.5\.0\t\/services/);
  assert.match(payload, /business\t1\.5\.0\t\/tools/);
  const changed = markerFor([
    { dependencyName: 'business', newVersion: '1.6.0', directory: '/services' },
    { dependencyName: 'business', newVersion: '1.5.0', directory: '/tools' },
  ]);
  assert.notEqual(marker, changed);
});

test('a security update uses newVersion from metadata', () => {
  const marker = markerFor([
    { dependencyName: 'lodash', newVersion: '4.17.21', directory: '/', updateType: 'version-update:semver-patch' },
  ]);
  assert.equal(payloadOf(marker), 'lodash\t4.17.21\t/');
  assert.notEqual(
    marker,
    markerFor([
      { dependencyName: 'lodash', newVersion: '4.17.22', directory: '/', updateType: 'version-update:semver-patch' },
    ]),
  );
});

test('reproduced Dependabot titles do not supply the marker', async () => {
  const cases = [
    {
      title: 'Bump business from 1.4.0 to 1.5.0 in the go_modules group across 1 directory',
      deps: [{ dependencyName: 'business', newVersion: '1.5.0', directory: '/', dependencyGroup: 'go_modules' }],
      payload: 'business\t1.5.0\t/',
    },
    {
      title: 'Bump business from 1.4.0 to 1.5.0 in /directory in the all-the-things group',
      deps: [
        { dependencyName: 'business', newVersion: '1.5.0', directory: '/directory', dependencyGroup: 'all-the-things' },
      ],
      payload: 'business\t1.5.0\t/directory',
    },
    {
      title: '[Security] Bump lodash from 4.17.20 to 4.17.21',
      deps: [{ dependencyName: 'lodash', newVersion: '4.17.21', directory: '/' }],
      payload: 'lodash\t4.17.21\t/',
    },
    {
      title: 'chore(deps): bump lodash from 4.17.20 to 4.17.21',
      deps: [{ dependencyName: 'lodash', newVersion: '4.17.21', directory: '/' }],
      payload: 'lodash\t4.17.21\t/',
    },
    {
      title: 'build(deps): bump lodash from 4.17.20 to 4.17.21',
      deps: [{ dependencyName: 'lodash', newVersion: '4.17.21', directory: '/' }],
      payload: 'lodash\t4.17.21\t/',
    },
    {
      title: 'Upgrade: Bump lodash from 4.17.20 to 4.17.21',
      deps: [{ dependencyName: 'lodash', newVersion: '4.17.21', directory: '/' }],
      payload: 'lodash\t4.17.21\t/',
    },
    {
      title: 'Upgrade: Update business requirement from ~> 1.4.0 to ~> 1.5.0',
      deps: [{ dependencyName: 'business', newVersion: '1.5.0', directory: '/' }],
      payload: 'business\t1.5.0\t/',
    },
  ];
  for (const item of cases) {
    const pr = {
      number: 42,
      title: item.title,
      body: 'Updates `business` from 1.4.0 to 1.5.0',
      user: { login: 'dependabot[bot]' },
      head: { sha: 'head' },
    };
    const reviewed = await resolve('pull_request', pr, {
      metadata: metadata(item.deps),
      commentsFor: () => [],
    });
    assert.equal(payloadOf(reviewed.core.outputs.review_marker), item.payload, item.title);
    const skipped = await resolve('pull_request', pr, { metadata: '', commentsFor: () => [] });
    assert.equal(skipped.core.outputs.review_marker, '', item.title);
    assert.equal(skipped.core.outputs.already_reviewed, 'false', item.title);
  }
});

test('missing metadata or a partial dependency list does not build a marker', () => {
  assert.equal(reviewMarkerFromMetadata(''), '');
  assert.equal(reviewMarkerFromMetadata('not json'), '');
  assert.equal(reviewMarkerFromMetadata('[]'), '');
  assert.equal(
    markerFor([
      { dependencyName: 'minimist', newVersion: '1.2.6', directory: '/' },
      { dependencyName: 'business', newVersion: '', directory: '/' },
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
    metadata: metadata(lodash('4.17.21')),
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
    metadata: metadata(lodash('4.17.22')),
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
    metadata: metadata(lodash('4.17.22')),
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
    metadata: metadata(lodash('4.17.22')),
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
    metadata: metadata(lodash('4.17.21')),
    commentsFor: () => [{ id: 7, user: { login: 'mallory' }, body: marker, created_at: '2026-01-01T00:00:00Z' }],
  });
  assert.equal(forged.core.outputs.already_reviewed, 'false');
  const legacy = await resolve('pull_request', pr, {
    metadata: metadata(lodash('4.17.21')),
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
    commentsFor: () => [botComment(marker)],
    inputs: { pr_number: '42' },
  });
  assert.equal(dispatched.core.outputs.already_reviewed, 'false');
  assert.equal(dispatched.core.outputs.review_marker, '');
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
  const { core } = await resolve('pull_request', pr, {
    metadata: metadata(lodash('4.17.21')),
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
