'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { parseDependencyUpdate } = require('./dependency-cursor-review-dependabot-context.js');

function rows(parsed) {
  return parsed.updates.map((item) => [item.packageName, item.fromVersion, item.toVersion, item.upstreamRepo]);
}

const RELEASE_NOTES = [
  '<details>',
  '<summary>Release notes</summary>',
  '<blockquote>',
  'Updates `other-lib` from 0.1.0 to 0.2.0',
  '<p>Upgrade path: `1.0.0` -> `9.9.9`</p>',
  '<details><summary>nested</summary>Updates `lodash` from 1.0.0 to 7.7.7</details>',
  '</blockquote>',
  '</details>',
].join('\n');

test('text inside <details> adds no package and disputes no version', () => {
  const body = [
    'Bumps [lodash](https://github.com/lodash/lodash) from 4.17.20 to 4.17.21.',
    RELEASE_NOTES,
    'Updates `lodash` from 4.17.20 to 4.17.21',
  ].join('\n');
  const parsed = parseDependencyUpdate('Bump lodash from 4.17.20 to 4.17.21', body);
  assert.deepEqual(rows(parsed), [['lodash', '4.17.20', '4.17.21', 'lodash/lodash']]);
});

test('the arrow fallback ignores release notes', () => {
  const body = ['https://github.com/example/example', RELEASE_NOTES].join('\n');
  const parsed = parseDependencyUpdate('Update dependency example to v1.2.3', body);
  assert.equal(parsed.fromVersion, '');
  assert.equal(parsed.toVersion, 'v1.2.3');
});

test('Release notes, Changelog and Commits links are not packages', () => {
  const body = [
    'Bumps [actions/checkout](https://github.com/actions/checkout) from 4 to 5.',
    '- [Release notes](https://github.com/actions/checkout/releases)',
    '- [Changelog](https://github.com/actions/checkout/blob/main/CHANGELOG.md)',
    '- [Commits](https://github.com/actions/checkout/compare/v4...v5)',
  ].join('\n');
  const parsed = parseDependencyUpdate('Bump actions/checkout from 4 to 5', body);
  assert.deepEqual(rows(parsed), [['actions/checkout', '4', '5', 'actions/checkout']]);
});

test('a group body that starts with Updates keeps its repositories', () => {
  const body = [
    'Updates the requirements on [clvm_tools](https://github.com/Chia-Network/clvm_tools) to permit the latest version.',
    '- [Release notes](https://github.com/Chia-Network/clvm_tools/releases)',
  ].join('\n');
  const parsed = parseDependencyUpdate('Update clvm_tools requirement from ==0.4.9 to ==0.4.10', body);
  assert.deepEqual(rows(parsed), [['clvm_tools', '0.4.9', '0.4.10', 'Chia-Network/clvm_tools']]);
});

test('a Renovate Package | Change table supplies versions and the source repository', () => {
  const body = [
    'This PR contains the following updates:',
    '',
    '| Package | Type | Update | Change |',
    '|---|---|---|---|',
    '| [@noble/hashes](https://paulmillr.com/noble) ([source](https://github.com/paulmillr/noble-hashes)) | dependencies | minor | [`1.3.0` -> `1.4.0`](https://renovatebot.com/diffs/npm/@noble%2fhashes/1.3.0/1.4.0) |',
    '| [docker/login-action](https://github.com/docker/login-action) | action | major | `v2` -> `v3` |',
  ].join('\n');
  const parsed = parseDependencyUpdate('Update dependencies', body);
  assert.deepEqual(rows(parsed), [
    ['@noble/hashes', '1.3.0', '1.4.0', 'paulmillr/noble-hashes'],
    ['docker/login-action', 'v2', 'v3', 'docker/login-action'],
  ]);
});

test('a sole update without a repository takes the body repository', () => {
  const body = 'This PR contains the following updates:\n\nSee https://github.com/Chia-Network/homebrew-chia for details.';
  const parsed = parseDependencyUpdate('Update dependency chia to v2.5.0', body);
  assert.equal(parsed.upstreamRepo, 'Chia-Network/homebrew-chia');
});

test('Terraform Registry links map to their GitHub repositories', () => {
  const provider = parseDependencyUpdate(
    'Update terraform aws to v5.1.0',
    '| Package | Type | Update | Change |\n|---|---|---|---|\n| [aws](https://registry.terraform.io/providers/hashicorp/aws) | required_provider | minor | `5.0.0` -> `5.1.0` |',
  );
  assert.equal(provider.updates.find((item) => item.packageName === 'aws').upstreamRepo, 'hashicorp/terraform-provider-aws');
  const module = parseDependencyUpdate(
    'Update terraform vpc to v5.1.0',
    '| Package | Type | Update | Change |\n|---|---|---|---|\n| [vpc](https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws) | module | minor | `5.0.0` -> `5.1.0` |',
  );
  assert.equal(
    module.updates.find((item) => item.packageName === 'vpc').upstreamRepo,
    'terraform-aws-modules/terraform-aws-vpc',
  );
});

test('constraint operators are stripped and a leading v or V is kept', () => {
  const body = 'Bumps [clvm](https://github.com/Chia-Network/clvm) from ==0.9.7 to >=0.9.8.';
  const parsed = parseDependencyUpdate('Bump clvm from ==0.9.7 to >=0.9.8', body);
  assert.deepEqual(rows(parsed), [['clvm', '0.9.7', '0.9.8', 'Chia-Network/clvm']]);
  const tagged = parseDependencyUpdate(
    'Bump tool from V1.0 to V1.1',
    'Bumps [tool](https://github.com/o/tool) from V1.0 to V1.1.\nUpdates `tool` from 1.0 to 1.1',
  );
  assert.deepEqual(rows(tagged), [['tool', 'V1.0', 'V1.1', 'o/tool']]);
  const renovate = parseDependencyUpdate('Update dependency ruff to v0.6.0', 'https://github.com/astral-sh/ruff');
  assert.equal(renovate.toVersion, 'v0.6.0');
});
