'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { parseDependencyUpdate } = require('./dependency-cursor-review-dependabot-context.js');

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

test('pip operators and npm ranges agree with the bare table', () => {
  const pipBody = [
    'Bumps [requests](https://github.com/psf/requests) from 2.31.0 to 2.32.0.',
    '| Package | From | To |',
    '| --- | --- | --- |',
    '| [requests](https://github.com/psf/requests) | `2.31.0` | `2.32.0` |',
    'Updates `requests` from 2.31.0 to 2.32.0',
  ].join('\n');
  const pip = parseDependencyUpdate('Update requests requirement from ==2.31.0 to ==2.32.0', pipBody);
  assert.deepEqual(
    pip.updates.map((item) => [item.packageName, item.fromVersion, item.toVersion, item.upstreamRepo]),
    [['requests', '2.31.0', '2.32.0', 'psf/requests']],
  );

  const npmBody = [
    'Bumps [lodash](https://github.com/lodash/lodash) from 4.17.20 to 4.17.21.',
    '| Package | From | To |',
    '| --- | --- | --- |',
    '| [lodash](https://github.com/lodash/lodash) | `4.17.20` | `4.17.21` |',
    'Updates `lodash` from 4.17.20 to 4.17.21',
  ].join('\n');
  const npm = parseDependencyUpdate('Update lodash requirement from ^4.17.20 to ^4.17.21', npmBody);
  assert.deepEqual(
    npm.updates.map((item) => [item.packageName, item.fromVersion, item.toVersion, item.upstreamRepo]),
    [['lodash', '4.17.20', '4.17.21', 'lodash/lodash']],
  );
});

test('a real version conflict stays unresolved after normalization', () => {
  const body = [
    'Bumps [lodash](https://github.com/lodash/lodash) from 4.17.20 to 4.17.21.',
    '| Package | From | To |',
    '| --- | --- | --- |',
    '| [lodash](https://github.com/lodash/lodash) | `4.17.20` | `4.17.21` |',
    'Updates `lodash` from 4.17.20 to 4.17.21',
  ].join('\n');
  const conflict = parseDependencyUpdate('Update lodash requirement from ^4.17.20 to ^9.9.9', body);
  assert.equal(conflict.updates[0].fromVersion, '4.17.20');
  assert.equal(conflict.updates[0].toVersion, '');
  const excluded = parseDependencyUpdate('Update lodash requirement from !=4.17.20 to ==4.17.21', body);
  assert.equal(excluded.updates[0].fromVersion, '');
  assert.equal(excluded.updates[0].toVersion, '4.17.21');
});

test('a release-note table does not invent packages or clear the update', () => {
  const body = [
    'Bumps [lodash](https://github.com/lodash/lodash) from 4.17.20 to 4.17.21.',
    '| Package | From | To |',
    '| --- | --- | --- |',
    '| [lodash](https://github.com/lodash/lodash) | `4.17.20` | `4.17.21` |',
    '',
    '| Package | From | To |',
    '| --- | --- | --- |',
    '| [lodash](https://github.com/evil/lodash) | `0.0.1` | `9.9.9` |',
    'Updates `lodash` from 4.17.20 to 4.17.21',
    '<details>',
    '<summary>Release notes</summary>',
    '| Package | From | To |',
    '| --- | --- | --- |',
    '| [lodash](https://github.com/evil/lodash) | `1.0.0` | `9.9.9` |',
    '| [left-pad](https://github.com/left-pad/left-pad) | `1.0.0` | `1.3.0` |',
    '</details>',
  ].join('\n');
  const parsed = parseDependencyUpdate('Bump lodash from 4.17.20 to 4.17.21', body);
  assert.deepEqual(
    parsed.updates.map((item) => [item.packageName, item.fromVersion, item.toVersion, item.upstreamRepo]),
    [['lodash', '4.17.20', '4.17.21', 'lodash/lodash']],
  );
});

