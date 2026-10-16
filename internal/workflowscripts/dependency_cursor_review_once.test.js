'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('child_process');
const crypto = require('node:crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');

const context = require('./dependency-cursor-review-dependabot-context.js');
const { run, MAX_PR_COMMITS } = require('./dependency-cursor-review-target-pr.js');
const postComment = require('./dependency-cursor-review-post-comment.js');

const {
  parseDependencyUpdate,
  patchIdFromDiff,
  reviewMarkerFromPatchId,
  reviewedShasForPatch,
  skipApplies,
  versionTextCameFromBody,
  MAX_DIFF_CHARS,
} = context;

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

function git(repo, args) {
  return execFileSync('git', args, {
    cwd: repo,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_TERMINAL_PROMPT: '0',
      GIT_EDITOR: 'true',
      GIT_SEQUENCE_EDITOR: 'true',
      GIT_PAGER: 'cat',
    },
  });
}

function initRepo() {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'dcr-git-'));
  git(repo, ['init', '-q', '-b', 'main']);
  git(repo, ['config', 'user.email', 't@example.com']);
  git(repo, ['config', 'user.name', 't']);
  return repo;
}

function commitAll(repo, message) {
  git(repo, ['add', '-A']);
  git(repo, ['commit', '-qm', message]);
}

function prDiff(repo) {
  return git(repo, ['diff', 'main...HEAD']);
}

function writeLines(repo, name, lines) {
  fs.writeFileSync(path.join(repo, name), `${lines.join('\n')}\n`);
}

function dependabotCommit({ author = 'dependabot[bot]', committer = 'web-flow', verified = true } = {}) {
  return {
    sha: 'abc',
    author: author ? { login: author } : null,
    committer: committer ? { login: committer } : null,
    commit: { message: 'bump', verification: { verified } },
  };
}

function botComment(marker) {
  return {
    id: 1,
    user: { login: 'github-actions[bot]' },
    body: `${marker}\n## review`,
    created_at: '2026-01-01T00:00:00Z',
  };
}

function fakeGithub({ pr, commentsFor = () => [], listError, commits = [], commitListError, diff = '', diffError }) {
  const calls = [];
  const api = {
    calls,
    rest: {
      pulls: {
        async get(params) {
          calls.push(['pulls.get', params]);
          if (params.mediaType?.format === 'diff') {
            if (diffError) throw diffError;
            return { data: diff };
          }
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

function dependabotPr(title) {
  return {
    number: 42,
    title,
    body: singleBody('abc1234'),
    user: { login: 'dependabot[bot]' },
    head: { sha: 'head' },
  };
}

function markerFor(diff, resolvedSha = 'a'.repeat(40)) {
  return reviewMarkerFromPatchId(patchIdFromDiff(diff), resolvedSha);
}

function realDiff() {
  if (realDiff.cached) return realDiff.cached;
  const repo = initRepo();
  try {
    fs.writeFileSync(path.join(repo, 'dep.txt'), 'base\n');
    commitAll(repo, 'base');
    git(repo, ['checkout', '-q', '-b', 'pr']);
    fs.writeFileSync(path.join(repo, 'dep.txt'), '1.5.0\n');
    commitAll(repo, 'bump');
    realDiff.cached = prDiff(repo);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
  return realDiff.cached;
}

function writeAgents(directory, malware, compatibility) {
  if (malware !== undefined) fs.writeFileSync(path.join(directory, 'cursor_output_malware.json'), malware ?? '');
  if (compatibility !== undefined) {
    fs.writeFileSync(path.join(directory, 'cursor_output_compatibility.json'), compatibility ?? '');
  }
}

function combinedOutput(malwareText, compatibilityText) {
  return `${JSON.stringify(
    {
      result: [
        '## Supply-Chain Malware Review',
        '',
        malwareText,
        '',
        '## Compatibility Analysis',
        '',
        compatibilityText,
      ].join('\n'),
      complete: true,
      malware_review: { result: malwareText },
      compatibility_review: { result: compatibilityText },
    },
    null,
    2,
  )}\n`;
}

test('patch-id is stable across rebase and commit message, and changes with content', () => {
  const repo = initRepo();
  try {
    writeLines(
      repo,
      'lock',
      Array.from({ length: 20 }, (_, index) => `line ${index + 1}`),
    );
    commitAll(repo, 'base');
    git(repo, ['checkout', '-q', '-b', 'pr']);
    const bumped = Array.from({ length: 20 }, (_, index) => (index === 9 ? 'line 10-bumped' : `line ${index + 1}`));
    writeLines(repo, 'lock', bumped);
    commitAll(repo, 'bump lock');
    const original = patchIdFromDiff(prDiff(repo));
    assert.match(original, /^[0-9a-f]{40}$/);

    git(repo, ['commit', '-q', '--amend', '-m', 'recreated bump with another message']);
    assert.equal(patchIdFromDiff(prDiff(repo)), original);

    git(repo, ['checkout', '-q', 'main']);
    fs.writeFileSync(path.join(repo, 'other.txt'), 'unrelated\n');
    commitAll(repo, 'move base');
    git(repo, ['checkout', '-q', 'pr']);
    git(repo, ['rebase', '-q', 'main']);
    assert.equal(patchIdFromDiff(prDiff(repo)), original);

    const newer = bumped.map((line, index) => (index === 9 ? 'line 10-newer' : line));
    writeLines(repo, 'lock', newer);
    commitAll(repo, 'newer version');
    const upgraded = patchIdFromDiff(prDiff(repo));
    assert.notEqual(upgraded, original);

    fs.writeFileSync(path.join(repo, 'notes.txt'), 'human\n');
    commitAll(repo, 'human follow-up');
    assert.notEqual(patchIdFromDiff(prDiff(repo)), upgraded);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('a lockfile context shift changes the patch id', () => {
  const repo = initRepo();
  try {
    const base = Array.from({ length: 20 }, (_, index) => `line ${index + 1}`);
    writeLines(repo, 'lock', base);
    commitAll(repo, 'base');
    git(repo, ['checkout', '-q', '-b', 'pr']);
    writeLines(
      repo,
      'lock',
      base.map((line, index) => (index === 9 ? 'line 10-bumped' : line)),
    );
    commitAll(repo, 'bump');
    const before = patchIdFromDiff(prDiff(repo));

    git(repo, ['checkout', '-q', 'main']);
    writeLines(
      repo,
      'lock',
      base.map((line, index) => (index === 7 ? 'line 8-context' : line)),
    );
    commitAll(repo, 'context');
    git(repo, ['checkout', '-q', '-b', 'shifted']);
    writeLines(
      repo,
      'lock',
      base.map((line, index) => {
        if (index === 7) return 'line 8-context';
        if (index === 9) return 'line 10-bumped';
        return line;
      }),
    );
    commitAll(repo, 'bump on shifted base');
    assert.notEqual(patchIdFromDiff(prDiff(repo)), before);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('one combined diff has one patch id and a commit series does not', () => {
  const repo = initRepo();
  try {
    fs.writeFileSync(path.join(repo, 'a.txt'), 'a\n');
    fs.writeFileSync(path.join(repo, 'b.txt'), 'b\n');
    commitAll(repo, 'base');
    git(repo, ['checkout', '-q', '-b', 'pr']);
    fs.writeFileSync(path.join(repo, 'a.txt'), 'A\n');
    commitAll(repo, 'a');
    fs.writeFileSync(path.join(repo, 'b.txt'), 'B\n');
    commitAll(repo, 'b');
    const combined = prDiff(repo);
    assert.match(patchIdFromDiff(combined), /^[0-9a-f]{40}$/);
    const series = git(repo, ['log', '-p', '--reverse', 'main..HEAD']);
    assert.equal(patchIdFromDiff(series), '');
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('marker build fails open on an empty, huge, or non-diff input', () => {
  assert.equal(patchIdFromDiff(''), '');
  assert.equal(patchIdFromDiff('not a diff\n'), '');
  assert.equal(patchIdFromDiff('x'.repeat(MAX_DIFF_CHARS + 1)), '');
  assert.equal(reviewMarkerFromPatchId(''), '');
  assert.equal(reviewMarkerFromPatchId('zzzz'), '');
  const id = 'a'.repeat(40);
  const sha = 'b'.repeat(40);
  assert.equal(reviewMarkerFromPatchId(id), '');
  assert.equal(reviewMarkerFromPatchId(id, 'zzzz'), '');
  assert.equal(reviewMarkerFromPatchId(id, sha), `<!-- cursor-dependabot-review patch-id:${id} resolved:${sha} -->`);
});

test('the same diff skips and a different diff or an old marker does not', async () => {
  const repo = initRepo();
  try {
    fs.writeFileSync(path.join(repo, 'dep.txt'), 'base\n');
    commitAll(repo, 'base');
    git(repo, ['checkout', '-q', '-b', 'pr']);
    fs.writeFileSync(path.join(repo, 'dep.txt'), '1.5.0\n');
    commitAll(repo, 'bump');
    const diff = prDiff(repo);
    const marker = markerFor(diff);
    fs.writeFileSync(path.join(repo, 'dep.txt'), '1.6.0\n');
    commitAll(repo, 'newer');
    const newer = markerFor(prDiff(repo));
    assert.notEqual(marker, newer);

    const pr = dependabotPr('Bump business from 1.4.0 to 1.5.0 in the go_modules group across 1 directory');
    const same = await resolve('pull_request', pr, {
      commits: [dependabotCommit()],
      diff,
      commentsFor: () => [botComment(marker)],
    });
    const reviewedSha = 'a'.repeat(40);
    assert.equal(same.core.outputs.review_marker, '');
    assert.equal(same.core.outputs.already_reviewed, 'false');
    assert.equal(same.core.outputs.reviewed_shas, reviewedSha);
    assert.equal(skipApplies(same.core.outputs.reviewed_shas.split(','), reviewedSha), true);
    assert.equal(skipApplies(same.core.outputs.reviewed_shas.split(','), 'b'.repeat(40)), false);

    const changed = await resolve('pull_request', pr, {
      commits: [dependabotCommit()],
      diff: prDiff(repo),
      commentsFor: () => [botComment(marker)],
    });
    assert.equal(changed.core.outputs.already_reviewed, 'false');
    assert.equal(changed.core.outputs.reviewed_shas, '');

    const quoted = await resolve('pull_request', pr, {
      commits: [dependabotCommit()],
      diff,
      commentsFor: () => [
        {
          id: 8,
          user: { login: 'github-actions[bot]' },
          body: `<!-- cursor-dependabot-review patch-id:${'b'.repeat(40)} -->\nquote ${marker}\n`,
          created_at: '2026-01-01T00:00:00Z',
        },
      ],
    });
    assert.equal(quoted.core.outputs.already_reviewed, 'false');
    assert.equal(quoted.core.outputs.reviewed_shas, '');

    const legacy = await resolve('pull_request', pr, {
      commits: [dependabotCommit()],
      diff,
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
    assert.equal(legacy.core.outputs.reviewed_shas, '');

    const patchOnly = `<!-- cursor-dependabot-review patch-id:${patchIdFromDiff(diff)} -->`;
    const unmarked = await resolve('pull_request', pr, {
      commits: [dependabotCommit()],
      diff,
      commentsFor: () => [botComment(patchOnly)],
    });
    assert.equal(unmarked.core.outputs.reviewed_shas, '');
    assert.equal(skipApplies([], 'a'.repeat(40)), false);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('a rebased pull request with a moved tag is not already reviewed', async () => {
  const repo = initRepo();
  try {
    fs.writeFileSync(path.join(repo, 'dep.txt'), 'base\n');
    commitAll(repo, 'base');
    git(repo, ['checkout', '-q', '-b', 'pr']);
    fs.writeFileSync(path.join(repo, 'dep.txt'), 'package==1.2.3\n');
    commitAll(repo, 'bump');
    const diff = prDiff(repo);
    const previous = 'a'.repeat(40);
    const moved = 'b'.repeat(40);
    const marker = markerFor(diff, previous);
    git(repo, ['checkout', '-q', 'main']);
    fs.writeFileSync(path.join(repo, 'other.txt'), 'unrelated\n');
    commitAll(repo, 'move base');
    git(repo, ['checkout', '-q', 'pr']);
    git(repo, ['rebase', '-q', 'main']);
    assert.equal(patchIdFromDiff(prDiff(repo)), patchIdFromDiff(diff));

    const pr = dependabotPr('Bump example from 1.2.2 to 1.2.3');
    const { core } = await resolve('pull_request', pr, {
      commits: [dependabotCommit()],
      diff: prDiff(repo),
      commentsFor: () => [botComment(marker)],
    });
    const reviewed = core.outputs.reviewed_shas.split(',').filter(Boolean);
    assert.deepEqual(reviewed, [previous]);
    assert.equal(skipApplies(reviewed, previous), true);
    assert.equal(skipApplies(reviewed, moved), false);
    assert.equal(reviewedShasForPatch([{ user: { login: 'mallory' }, body: marker }], patchIdFromDiff(diff)).length, 0);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('release note versions are marked only when they supply a missing version', () => {
  const titled = 'Bump example from 1.0.0 to 1.1.0';
  const notes = '`9.9.9` -> `9.9.9`\nhttps://github.com/example/example';
  const kept = parseDependencyUpdate(titled, notes);
  assert.equal(kept.fromVersion, '1.0.0');
  assert.equal(kept.toVersion, '1.1.0');
  assert.equal(versionTextCameFromBody(titled, notes), false);

  const renovate = 'Update dependency example to v1.2.3';
  const same = '`1.2.3` -> `1.2.3`\nhttps://github.com/example/example';
  const filled = parseDependencyUpdate(renovate, same);
  assert.equal(filled.fromVersion, '1.2.3');
  assert.equal(filled.toVersion, '1.2.3');
  assert.equal(versionTextCameFromBody(renovate, same), true);

  const open = 'Update dependency example to v1.2.3';
  assert.equal(versionTextCameFromBody(open, 'https://github.com/example/example'), false);
});

test('a non-web-flow committer, unverified commit, or other author fails open', async () => {
  const pr = dependabotPr('Bump lodash from 4.17.20 to 4.17.21');
  const diff = realDiff();
  const cases = [
    [dependabotCommit(), dependabotCommit({ committer: 'v-sachin-sandhu' })],
    [dependabotCommit({ verified: false })],
    [dependabotCommit({ author: 'maintainer' })],
    [dependabotCommit({ author: '' })],
  ];
  for (const commits of cases) {
    const { core } = await resolve('pull_request', pr, { commits, diff, commentsFor: () => [] });
    assert.equal(core.outputs.review_marker, '');
    assert.equal(core.outputs.already_reviewed, 'false');
  }
});

test('pagination sees a bad commit past the first page', async () => {
  const commits = Array.from({ length: 30 }, () => dependabotCommit());
  commits.push(dependabotCommit({ committer: 'maintainer' }));
  const pr = dependabotPr('Bump the group');
  const { core, github } = await resolve('pull_request', pr, {
    commits,
    diff: realDiff(),
    commentsFor: () => [],
  });
  assert.equal(
    github.calls.some((call) => call[0] === 'paginate' && call[1] === github.rest.pulls.listCommits),
    true,
  );
  assert.equal(core.outputs.review_marker, '');
  assert.equal(core.outputs.already_reviewed, 'false');
});

test('an empty commit list, an API error, an empty diff, or too many commits fails open', async () => {
  const pr = dependabotPr('Bump lodash from 4.17.20 to 4.17.21');
  const good = { commits: [dependabotCommit()], commentsFor: () => [] };

  const empty = await resolve('pull_request', pr, { ...good, commits: [] });
  assert.equal(empty.core.outputs.review_marker, '');

  const failed = await resolve('pull_request', pr, { ...good, commitListError: new Error('rate limit') });
  assert.equal(failed.core.outputs.review_marker, '');
  assert.match(failed.core.warnings.join('\n'), /rate limit/);

  const tooMany = Array.from({ length: MAX_PR_COMMITS + 1 }, () => dependabotCommit());
  const bounded = await resolve('pull_request', pr, { ...good, commits: tooMany });
  assert.equal(bounded.core.outputs.review_marker, '');

  const noDiff = await resolve('pull_request', pr, { ...good, diff: '' });
  assert.equal(noDiff.core.outputs.review_marker, '');

  const refused = await resolve('pull_request', pr, { ...good, diffError: new Error('diff too large') });
  assert.equal(refused.core.outputs.review_marker, '');
  assert.equal(refused.core.outputs.already_reviewed, 'false');
  assert.match(refused.core.warnings.join('\n'), /diff too large/);
});

test('parseDependencyUpdate still extracts upstream notes and commits', () => {
  const parsed = parseDependencyUpdate('Bump lodash from 4.17.20 to 4.17.21', singleBody('deadbee'));
  assert.equal(parsed.upstreamRepo, 'lodash/lodash');
  assert.equal(parsed.packageName, 'lodash');
  assert.equal(parsed.fromVersion, '4.17.20');
  assert.equal(parsed.toVersion, '4.17.21');
  assert.equal(parsed.updates.length, 1);
  assert.equal(parsed.updates[0].fromVersion, '4.17.20');
  assert.equal(parsed.updates[0].toVersion, '4.17.21');
  assert.match(parsed.releaseNotes, /small patch/);
  assert.match(parsed.commits, /deadbee/);
});

test('parseDependencyUpdate reads a grouped npm table', () => {
  const body = [
    'Bumps the npm-dependencies group with 2 updates in the / directory:',
    '| Package | From | To |',
    '| --- | --- | --- |',
    '| [lodash](https://github.com/lodash/lodash) | `4.17.20` | `4.17.21` |',
    '| [semver](https://github.com/npm/node-semver) | `7.5.4` | `7.6.0` |',
    '| [@rollup/plugin-commonjs](https://github.com/rollup/plugins/tree/HEAD/packages/commonjs) | `29.0.2` | `29.0.3` |',
    'Updates `lodash` from 4.17.20 to 4.17.21',
    'Updates `semver` from 7.5.4 to 7.6.0',
    'Updates `@rollup/plugin-commonjs` from 29.0.2 to 29.0.3',
  ].join('\n');
  const parsed = parseDependencyUpdate('Bump the npm-dependencies group across 1 directory with 2 updates', body);
  assert.deepEqual(
    parsed.updates.map((item) => [item.packageName, item.fromVersion, item.toVersion, item.upstreamRepo]),
    [
      ['lodash', '4.17.20', '4.17.21', 'lodash/lodash'],
      ['semver', '7.5.4', '7.6.0', 'npm/node-semver'],
      ['@rollup/plugin-commonjs', '29.0.2', '29.0.3', 'rollup/plugins'],
    ],
  );
  assert.equal(parsed.packageName, '');
  assert.equal(parsed.upstreamRepo, '');
  assert.equal(parsed.fromVersion, '');
  assert.equal(parsed.toVersion, '');
});

test('parseDependencyUpdate reads a real group of three without a table', () => {
  const body = [
    'Bumps the codeql-actions group with 3 updates: [github/codeql-action/init](https://github.com/github/codeql-action), [github/codeql-action/analyze](https://github.com/github/codeql-action) and [github/codeql-action/upload-sarif](https://github.com/github/codeql-action).',
    '',
    'Updates `github/codeql-action/init` from 4.38.2 to 4.38.3',
    '<details>',
    '<summary>Release notes</summary>',
    '<a href="https://github.com/evil/decoy">decoy</a>',
    '</details>',
    'Updates `github/codeql-action/analyze` from 4.38.2 to 4.38.3',
    'Updates `github/codeql-action/upload-sarif` from 4.38.2 to 4.38.3',
  ].join('\n');
  const parsed = parseDependencyUpdate('Bump the codeql-actions group with 3 updates', body);
  assert.deepEqual(
    parsed.updates.map((item) => [item.packageName, item.fromVersion, item.toVersion, item.upstreamRepo]),
    [
      ['github/codeql-action/init', '4.38.2', '4.38.3', 'github/codeql-action'],
      ['github/codeql-action/analyze', '4.38.2', '4.38.3', 'github/codeql-action'],
      ['github/codeql-action/upload-sarif', '4.38.2', '4.38.3', 'github/codeql-action'],
    ],
  );
});

test('parseDependencyUpdate reads a real group of five with a table', () => {
  const body = [
    'Bumps the actions group with 5 updates:',
    '',
    '| Package | From | To |',
    '| --- | --- | --- |',
    '| [actions/checkout](https://github.com/actions/checkout) | `4` | `7` |',
    '| [actions/setup-node](https://github.com/actions/setup-node) | `4` | `7` |',
    '| [actions/setup-java](https://github.com/actions/setup-java) | `4` | `6` |',
    '| [actions/upload-artifact](https://github.com/actions/upload-artifact) | `4` | `7` |',
    '| [actions/download-artifact](https://github.com/actions/download-artifact) | `4` | `8` |',
    '',
    'Updates `actions/checkout` from 4 to 7',
    'Updates `actions/setup-node` from 4 to 7',
    'Updates `actions/setup-java` from 4 to 6',
    'Updates `actions/upload-artifact` from 4 to 7',
    'Updates `actions/download-artifact` from 4 to 8',
  ].join('\n');
  const parsed = parseDependencyUpdate('Bump the actions group with 5 updates', body);
  assert.deepEqual(
    parsed.updates.map((item) => [item.packageName, item.fromVersion, item.toVersion, item.upstreamRepo]),
    [
      ['actions/checkout', '4', '7', 'actions/checkout'],
      ['actions/setup-node', '4', '7', 'actions/setup-node'],
      ['actions/setup-java', '4', '6', 'actions/setup-java'],
      ['actions/upload-artifact', '4', '7', 'actions/upload-artifact'],
      ['actions/download-artifact', '4', '8', 'actions/download-artifact'],
    ],
  );
});

test('a disagreeing repository or version clears that field', () => {
  const body = [
    'Bumps [lodash](https://github.com/evil/lodash) from 4.17.20 to 4.17.21.',
    '| Package | From | To |',
    '| --- | --- | --- |',
    '| [lodash](https://github.com/lodash/lodash) | `4.17.20` | `9.9.9` |',
    'Updates `lodash` from 4.17.20 to 4.17.21',
  ].join('\n');
  const parsed = parseDependencyUpdate('Bump lodash from 4.17.20 to 4.17.21', body);
  assert.equal(parsed.updates.length, 1);
  assert.equal(parsed.updates[0].packageName, 'lodash');
  assert.equal(parsed.updates[0].upstreamRepo, '');
  assert.equal(parsed.updates[0].fromVersion, '4.17.20');
  assert.equal(parsed.updates[0].toVersion, '');
});

test('an extra Updates line does not drop the title package', () => {
  const body = [
    'Bumps [lodash](https://github.com/lodash/lodash) from 4.17.20 to 4.17.21.',
    'Updates `left-pad` from 1.0.0 to 1.1.0',
  ].join('\n');
  const parsed = parseDependencyUpdate('Bump lodash from 4.17.20 to 4.17.21', body);
  const names = parsed.updates.map((item) => item.packageName);
  assert.deepEqual(names, ['lodash', 'left-pad']);
  assert.equal(parsed.updates[0].upstreamRepo, 'lodash/lodash');
  assert.equal(parsed.updates[0].toVersion, '4.17.21');
});

test('parseDependencyUpdate reads a grouped gomod list and leaves an unresolvable entry', () => {
  const body = [
    'Bumps the gomod group with 2 updates in the / directory:',
    '| Package | From | To |',
    '| --- | --- | --- |',
    '| [github.com/spf13/cobra](https://github.com/spf13/cobra) | `1.8.0` | `1.8.1` |',
    '| k8s.io/api | `0.29.1` | `0.29.2` |',
    'Updates `github.com/spf13/cobra` from 1.8.0 to 1.8.1',
    'Updates `k8s.io/api` from 0.29.1 to 0.29.2',
    'Updates `github.com/mattn/go-runewidth` from 0.0.15 to 0.0.16',
  ].join('\n');
  const parsed = parseDependencyUpdate('Bump the gomod group across 1 directory with 3 updates', body);
  const byName = Object.fromEntries(parsed.updates.map((item) => [item.packageName, item]));
  assert.equal(byName['github.com/spf13/cobra'].upstreamRepo, 'spf13/cobra');
  assert.equal(byName['github.com/spf13/cobra'].toVersion, '1.8.1');
  assert.equal(byName['k8s.io/api'].upstreamRepo, '');
  assert.equal(byName['k8s.io/api'].fromVersion, '0.29.1');
  assert.equal(byName['github.com/mattn/go-runewidth'].upstreamRepo, 'mattn/go-runewidth');
  assert.equal(parsed.upstreamRepo, '');
  assert.equal(parsed.packageName, '');
});

test('grouped context does not choose a package before the scans', async () => {
  await withWorkspace(async (directory) => {
    process.env.PR_TITLE = 'Bump the npm-dependencies group across 1 directory with 2 updates';
    process.env.PR_BODY = [
      '| Package | From | To |',
      '| --- | --- | --- |',
      '| [lodash](https://github.com/lodash/lodash) | `4.17.20` | `4.17.21` |',
      '| [semver](https://github.com/npm/node-semver) | `7.5.4` | `7.6.0` |',
    ].join('\n');
    process.env.PR_NUMBER = '7';
    const core = fakeCore();
    await context({ core });
    assert.equal(core.failed, '');
    assert.equal(core.outputs.package_name, '');
    assert.equal(core.outputs.upstream_repo, '');
    const updates = JSON.parse(fs.readFileSync(path.join(directory, 'dependency_updates.json'), 'utf8'));
    assert.deepEqual(
      updates.map((item) => item.packageName),
      ['lodash', 'semver'],
    );
  });
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
    const updates = JSON.parse(fs.readFileSync(path.join(directory, 'dependency_updates.json'), 'utf8'));
    assert.equal(updates.length, 1);
    assert.equal(updates[0].packageName, 'lodash');
    assert.equal(updates[0].fromVersion, '4.17.20');
    assert.equal(updates[0].toVersion, '4.17.21');
    assert.equal(updates[0].upstreamRepo, 'lodash/lodash');
  });
});

test('a new pull request is reviewed even for a diff reviewed elsewhere', async () => {
  const repo = initRepo();
  try {
    fs.writeFileSync(path.join(repo, 'dep.txt'), 'base\n');
    commitAll(repo, 'base');
    git(repo, ['checkout', '-q', '-b', 'pr']);
    fs.writeFileSync(path.join(repo, 'dep.txt'), '1.5.0\n');
    commitAll(repo, 'bump');
    const marker = markerFor(prDiff(repo));
    const pr = { ...dependabotPr('Bump lodash'), number: 99 };
    const { core } = await resolve('pull_request', pr, {
      commits: [dependabotCommit()],
      diff: prDiff(repo),
      commentsFor: (number) => (number === 42 ? [botComment(marker)] : []),
    });
    assert.equal(core.outputs.already_reviewed, 'false');
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('a forged marker does not suppress the review', async () => {
  const repo = initRepo();
  try {
    fs.writeFileSync(path.join(repo, 'dep.txt'), 'base\n');
    commitAll(repo, 'base');
    git(repo, ['checkout', '-q', '-b', 'pr']);
    fs.writeFileSync(path.join(repo, 'dep.txt'), '1.5.0\n');
    commitAll(repo, 'bump');
    const marker = markerFor(prDiff(repo));
    const forged = await resolve('pull_request', dependabotPr('Bump lodash'), {
      commits: [dependabotCommit()],
      diff: prDiff(repo),
      commentsFor: () => [{ id: 7, user: { login: 'mallory' }, body: marker, created_at: '2026-01-01T00:00:00Z' }],
    });
    assert.equal(forged.core.outputs.already_reviewed, 'false');
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('Renovate and workflow_dispatch still review when a marker exists', async () => {
  const repo = initRepo();
  try {
    fs.writeFileSync(path.join(repo, 'dep.txt'), 'base\n');
    commitAll(repo, 'base');
    git(repo, ['checkout', '-q', '-b', 'pr']);
    fs.writeFileSync(path.join(repo, 'dep.txt'), '1.5.0\n');
    commitAll(repo, 'bump');
    const diff = prDiff(repo);
    const marker = markerFor(diff);
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

    const dispatched = await resolve('workflow_dispatch', dependabotPr('Bump lodash'), {
      commits: [dependabotCommit()],
      diff,
      commentsFor: () => [botComment(marker)],
      inputs: { pr_number: '42' },
    });
    assert.equal(dispatched.core.outputs.already_reviewed, 'false');
    assert.equal(dispatched.core.outputs.review_marker, '');
    assert.equal(reviewMarkerFromPatchId(dispatched.core.outputs.patch_id, 'a'.repeat(40)), marker);
    assert.equal(
      dispatched.github.calls.some((call) => call[0] === 'listComments'),
      false,
    );
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('comment listing failure runs the review instead of skipping it', async () => {
  const repo = initRepo();
  try {
    fs.writeFileSync(path.join(repo, 'dep.txt'), 'base\n');
    commitAll(repo, 'base');
    git(repo, ['checkout', '-q', '-b', 'pr']);
    fs.writeFileSync(path.join(repo, 'dep.txt'), '1.5.0\n');
    commitAll(repo, 'bump');
    const { core } = await resolve('pull_request', dependabotPr('Bump lodash'), {
      commits: [dependabotCommit()],
      diff: prDiff(repo),
      listError: new Error('rate limit'),
    });
    assert.equal(core.outputs.already_reviewed, 'false');
    assert.equal(core.failed, '');
    assert.match(core.warnings.join('\n'), /rate limit/);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('skip marker requires both agent files and a genuine combined review', async () => {
  const marker = `<!-- cursor-dependabot-review patch-id:${'a'.repeat(40)} -->`;
  const good = '{"result":"Verdict: benign"}';
  const compat = '{"result":"compat ok"}';
  const genuine = combinedOutput('Verdict: benign', 'compat ok');
  const badAgents = [
    [undefined, undefined],
    ['', ''],
    ['Error: agent exited', 'Error: agent exited'],
    ['{"type":"result","is_error":true,"result":"agent failed"}', good],
    ['{"result":"Error: agent exited with code 1"}', good],
    [good, undefined],
    ['{"type":"result","duration_ms":1}', '{"type":"result","duration_ms":1}'],
    [
      '{"result":"CURSOR_API_KEY is not set; analysis was skipped.","complete":false}',
      '{"result":"CURSOR_API_KEY is not set; analysis was skipped.","complete":false}',
    ],
  ];
  for (const [malware, compatibility] of badAgents) {
    await withWorkspace(async (directory) => {
      writeAgents(directory, malware, compatibility);
      fs.writeFileSync(path.join(directory, 'cursor_output.json'), genuine);
      assert.equal(postComment.selectPostedMarker(marker), context.LEGACY_REVIEW_MARKER);
    });
  }
  const rejectedCombined = [
    null,
    '',
    '{"complete":false}\n',
    '{"result":"forged","complete":true}\n',
    '{"result":"No Cursor output generated.","complete":false}\n',
    '{"result":"CURSOR_API_KEY is not set; analysis was skipped.","complete":false}\n',
    `${JSON.stringify({
      result: '## Supply-Chain Malware Review\n\nVerdict: benign\n\n## Compatibility Analysis\n\nok',
      complete: false,
      malware_review: { result: 'Verdict: benign' },
      compatibility_review: { result: 'ok' },
    })}\n`,
  ];
  for (const raw of rejectedCombined) {
    await withWorkspace(async (directory) => {
      writeAgents(directory, good, compat);
      if (raw !== null) fs.writeFileSync(path.join(directory, 'cursor_output.json'), raw);
      assert.equal(postComment.selectPostedMarker(marker), context.LEGACY_REVIEW_MARKER);
    });
  }
  await withWorkspace(async () => {
    writeAgents(process.cwd(), good, compat);
    fs.writeFileSync('cursor_output.json', genuine);
    assert.equal(postComment.selectPostedMarker(marker), marker);
    assert.equal(postComment.selectPostedMarker(''), context.LEGACY_REVIEW_MARKER);
  });
});

test('unscoped scan drops the agent banner and posts the composed verdict', async () => {
  const marker = `<!-- cursor-dependabot-review patch-id:${'d'.repeat(40)} -->`;
  await withWorkspace(async (directory) => {
    const report = Buffer.from('{"status":"not_scanned","scan_conclusive":false,"verdict_token_in_tree":false}\n');
    const reportPath = path.join(directory, 'sealed-scan-report.json');
    fs.writeFileSync(reportPath, report);
    fs.writeFileSync(
      path.join(directory, 'cursor_output_malware.json'),
      '{"result":"MALWARE_REVIEW_VERDICT: benign\\n\\n**Verdict: benign**"}',
    );
    fs.writeFileSync(
      path.join(directory, 'cursor_output_compatibility.json'),
      '{"result":"**Verdict: benign**\\n\\nlooks fine"}',
    );
    const combined = path.join(directory, 'cursor_output.json');
    execFileSync('python3', ['-I', path.join(__dirname, 'dependency_cursor_review_combine_outputs.py')], {
      cwd: directory,
      env: {
        ...process.env,
        DCR_SCAN_REPORT: reportPath,
        DCR_MALWARE_JSON: path.join(directory, 'cursor_output_malware.json'),
        DCR_COMPAT_JSON: path.join(directory, 'cursor_output_compatibility.json'),
        DCR_COMBINED_JSON: combined,
        MALWARE_SCAN_REPORT_SHA256: crypto.createHash('sha256').update(report).digest('hex'),
      },
    });
    const written = JSON.parse(fs.readFileSync(combined, 'utf8'));
    assert.equal(written.complete, false);
    assert.equal(JSON.stringify(written.malware_review).includes('**Verdict: benign**'), false);
    assert.equal(written.result.includes('**Verdict: malicious**'), true);
    process.env.REVIEW_MARKER = marker;
    process.env.PR_NUMBER = '42';
    const github = fakeGithub({ commentsFor: () => [] });
    await postComment({
      github,
      context: { repo: { owner: 'acme', repo: 'widgets' } },
      core: fakeCore(),
    });
    const created = github.calls.find((call) => call[0] === 'createComment');
    const body = created[1].body;
    assert.equal(body.split('\n')[0], context.LEGACY_REVIEW_MARKER);
    assert.equal(body.includes('patch-id:'), false);
    assert.equal(body.includes('**Verdict: benign**'), false);
    assert.equal(body.includes('**Verdict: malicious**'), true);
    assert.equal(body.includes('needs human review'), false);
  });
});

test('a missing combined review posts the legacy marker with the fallback body', async () => {
  const marker = `<!-- cursor-dependabot-review patch-id:${'b'.repeat(40)} -->`;
  await withWorkspace(async (directory) => {
    process.env.REVIEW_MARKER = marker;
    process.env.PR_NUMBER = '42';
    writeAgents(directory, '{"result":"Verdict: benign"}', '{"result":"compat ok"}');
    const github = fakeGithub({ commentsFor: () => [] });
    await postComment({
      github,
      context: { repo: { owner: 'acme', repo: 'widgets' } },
      core: fakeCore(),
    });
    const created = github.calls.find((call) => call[0] === 'createComment');
    assert.equal(created[1].body.startsWith(context.LEGACY_REVIEW_MARKER), true);
    assert.equal(created[1].body.includes('patch-id:'), false);
    assert.match(created[1].body, /No Cursor output generated/);
  });
});

test('completed analysis updates an Actions bot marker and treats a human quote as commentary', async () => {
  const marker = `<!-- cursor-dependabot-review patch-id:${'c'.repeat(40)} -->`;
  await withWorkspace(async (directory) => {
    process.env.REVIEW_MARKER = marker;
    process.env.PR_NUMBER = '42';
    writeAgents(directory, '{"result":"Verdict: benign"}', '{"result":"compat ok"}');
    fs.writeFileSync(path.join(directory, 'cursor_output.json'), combinedOutput('Verdict: benign', 'compat ok'));
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
          body: 'Coverage report\n<!-- cursor-dependabot-review quoted in the body',
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

test('trusted scripts survive a workspace wipe', () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'dcr-ws-'));
  const runner = fs.mkdtempSync(path.join(os.tmpdir(), 'dcr-runner-'));
  try {
    const scripts = path.join(workspace, '.github', 'scripts');
    fs.mkdirSync(scripts, { recursive: true });
    for (const name of [
      'dependency-cursor-review-target-pr.js',
      'dependency-cursor-review-dependabot-context.js',
      'dependency-cursor-review-post-comment.js',
    ]) {
      fs.copyFileSync(path.join(__dirname, name), path.join(scripts, name));
    }
    const dest = path.join(runner, 'trusted-dcr-helper');
    fs.cpSync(scripts, dest, { recursive: true });
    fs.rmSync(workspace, { recursive: true, force: true });
    assert.equal(fs.existsSync(workspace), false);
    const loadedPost = require(path.join(dest, 'dependency-cursor-review-post-comment.js'));
    const loadedTarget = require(path.join(dest, 'dependency-cursor-review-target-pr.js'));
    assert.equal(typeof loadedPost.selectPostedMarker, 'function');
    assert.equal(typeof loadedTarget.run, 'function');
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
    fs.rmSync(runner, { recursive: true, force: true });
  }
});
