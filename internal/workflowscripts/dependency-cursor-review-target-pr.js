'use strict';

/**
 * Resolve Dependabot/Renovate PR context for dependency-cursor-review (workflow step target_pr).
 */
async function run({ github, context, core }) {
  let pr;
  if (context.eventName === 'pull_request') {
    pr = context.payload.pull_request;
  } else {
    const raw = context.payload.inputs?.pr_number;
    const prNumber = Number(raw);
    if (!Number.isInteger(prNumber) || prNumber <= 0) {
      core.setFailed(`Invalid pr_number input: ${raw}`);
      return;
    }
    const { data } = await github.rest.pulls.get({
      owner: context.repo.owner,
      repo: context.repo.repo,
      pull_number: prNumber,
    });
    pr = data;
  }
  if (!pr) {
    core.setFailed('Could not resolve target pull request context.');
    return;
  }
  const allowedBots = ['dependabot[bot]', 'renovate[bot]'];
  if (!allowedBots.includes(pr.user?.login)) {
    core.setFailed(
      `Target PR #${pr.number} is not opened by an allowed bot. Author: ${pr.user?.login}`
    );
    return;
  }
  core.setOutput('number', String(pr.number));
  core.setOutput('title', pr.title || '');
  core.setOutput('body', pr.body || '');
  core.setOutput('head_sha', pr.head?.sha || '');
}

module.exports = { run };
