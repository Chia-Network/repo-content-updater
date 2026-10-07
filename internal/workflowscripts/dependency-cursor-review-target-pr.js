'use strict';

/**
 * Resolve Dependabot/Renovate PR context for dependency-cursor-review (workflow step target_pr).
 *
 * Dependabot pull_request events also fire on rebase, recreate, and rebuild.
 * Those later pushes skip the review when github-actions[bot] has already
 * commented the marker for this same upgrade. "Same" is the GitHub PR number
 * plus the dependency target version (not the head SHA). A new PR has no
 * marker, so it is reviewed. A new target version on this PR does not match
 * the old marker, so it is reviewed. Renovate and workflow_dispatch are unchanged.
 */
const {
  isActionsBotUpgradeReview,
  reviewMarkerForUpgrade,
} = require('./dependency-cursor-review-dependabot-context.js');

const DEPENDABOT_BOT = 'dependabot[bot]';

async function listIssueComments(github, context, prNumber) {
  const comments = await github.paginate(github.rest.issues.listComments, {
    owner: context.repo.owner,
    repo: context.repo.repo,
    issue_number: prNumber,
    per_page: 100,
  });
  return Array.isArray(comments) ? comments : [];
}

async function dependabotReviewAlreadyPosted({ github, context, core, pr, marker }) {
  if (context.eventName !== 'pull_request') return false;
  if (pr.user?.login !== DEPENDABOT_BOT) return false;
  if (!marker) {
    core.notice('Dependabot PR has no stable dependency-version identity; running review.');
    return false;
  }
  let comments;
  try {
    comments = await listIssueComments(github, context, pr.number);
  } catch (err) {
    core.warning(`Could not list PR comments to detect an existing review (${err.message}); running review.`);
    return false;
  }
  const matched = comments.some((comment) => isActionsBotUpgradeReview(comment, marker));
  if (matched) {
    core.notice(`Dependabot PR #${pr.number} already has a Cursor review for this dependency upgrade; skipping.`);
  }
  return matched;
}

async function run({ github, context, core }) {
  core.setOutput('already_reviewed', 'false');
  core.setOutput('review_marker', '');
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
  const allowedBots = [DEPENDABOT_BOT, 'renovate[bot]'];
  if (!allowedBots.includes(pr.user?.login)) {
    core.setFailed(`Target PR #${pr.number} is not opened by an allowed bot. Author: ${pr.user?.login}`);
    return;
  }
  const marker = pr.user?.login === DEPENDABOT_BOT ? reviewMarkerForUpgrade(pr.title || '', pr.body || '') : '';
  core.setOutput('number', String(pr.number));
  core.setOutput('title', pr.title || '');
  core.setOutput('body', pr.body || '');
  core.setOutput('head_sha', pr.head?.sha || '');
  core.setOutput('review_marker', marker);
  const alreadyReviewed = await dependabotReviewAlreadyPosted({
    github,
    context,
    core,
    pr,
    marker,
  });
  core.setOutput('already_reviewed', alreadyReviewed ? 'true' : 'false');
}

module.exports = { run };
