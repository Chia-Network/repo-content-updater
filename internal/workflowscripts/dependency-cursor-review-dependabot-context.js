'use strict';

const fs = require('fs');

// The review marker is produced once, here, and passed through as that single line.

const LEGACY_REVIEW_MARKER = '<!-- cursor-dependabot-review -->';
const ACTIONS_BOT_LOGIN = 'github-actions[bot]';

function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function extractDetailsSection(text, summaryLabel) {
  const summaryRe = new RegExp(`<details[^>]*>\\s*<summary>\\s*${escapeRegex(summaryLabel)}[^<]*</summary>`, 'i');
  const summaryMatch = summaryRe.exec(text);
  if (!summaryMatch) return '';

  const start = summaryMatch.index;
  const tagRe = /<details\b[^>]*>|<\/details>/gi;
  tagRe.lastIndex = start;
  let depth = 0;
  let end = -1;
  let tag;

  while ((tag = tagRe.exec(text)) !== null) {
    if (tag[0].toLowerCase().startsWith('<details')) {
      depth += 1;
    } else {
      depth -= 1;
    }
    if (depth === 0) {
      end = tagRe.lastIndex;
      break;
    }
  }

  if (end === -1) return '';
  const block = text.slice(start, end);
  return block
    .replace(summaryRe, '')
    .replace(/<\/details>\s*$/i, '')
    .trim();
}

function parseDependencyUpdate(title, body) {
  const dependencyRepoMatch = body.match(
    /^\s*(?:Bumps|Update(?:s|d)?)\s+\[[^\]]+\]\(\s*https?:\/\/(?:redirect\.)?github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)(?:[\/#?][^)\s]*)?\s*\)/im,
  );
  const repoMatch =
    dependencyRepoMatch ||
    body.match(/https?:\/\/(?:redirect\.)?github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)(?=\/|$|[)\]>\s"'?#])/i);
  const upstreamRepo = repoMatch ? repoMatch[1].replace(/\.git$/i, '') : '';

  let releaseNotes = extractDetailsSection(body, 'Release notes');
  if (!releaseNotes && upstreamRepo) {
    releaseNotes = extractDetailsSection(body, upstreamRepo);
  }
  if (!releaseNotes) {
    const rnHeading = body.match(/###\s*Release\s+Notes?\s*\n([\s\S]*?)(?=\n---|\n###\s|$)/i);
    if (rnHeading) releaseNotes = rnHeading[1].trim();
  }

  let commits = extractDetailsSection(body, 'Commits');
  if (!commits) {
    const shaMatches = body.match(/\b[0-9a-f]{7,40}\b/gi);
    if (shaMatches && shaMatches.length > 0) commits = shaMatches.join('\n');
  }

  const titled = dependabotTitleVersions(title);
  const renovateTitleMatch =
    !titled &&
    (title.match(/(?:update|pin)\s+dependency\s+(.+?)\s+to\s+v?([^\s]+)/i) ||
      title.match(/(?:update|pin)\s+(.+?)\s+(?:action|digest|docker\s+tag)\s+to\s+v?([^\s]+)/i) ||
      title.match(/(?:update|pin)\s+(.+?)\s+to\s+v?([^\s]+)/i));

  let packageName;
  let fromVersion;
  let toVersion;
  if (titled) {
    packageName = titled.packageName;
    fromVersion = titled.fromVersion;
    toVersion = titled.toVersion;
  } else if (renovateTitleMatch) {
    packageName = renovateTitleMatch[1].trim();
    fromVersion = '';
    toVersion = renovateTitleMatch[2].trim();
  } else {
    packageName = '';
    fromVersion = '';
    toVersion = '';
  }

  if (!fromVersion || !toVersion) {
    const bodyVersionMatch = body.match(/`([^`\s]+)`\s*(?:->|→)\s*`([^`\s]+)`/);
    if (bodyVersionMatch) {
      if (!fromVersion) fromVersion = bodyVersionMatch[1].replace(/^v/i, '');
      if (!toVersion) toVersion = bodyVersionMatch[2].replace(/^v/i, '');
    }
  }

  return {
    upstreamRepo,
    packageName,
    fromVersion,
    toVersion,
    releaseNotes,
    commits,
  };
}

function cleanVersionToken(value) {
  return String(value || '')
    .trim()
    .replace(/[.,;:)]+$/g, '');
}

const VERSION_CLAUSE = '(?:~>|>=|<=|!=|\\^|~|>|<)\\s+\\S+|\\S+';

/** Shared by the prompt parser and the skip token. Null when this is not a from/to title. */
function dependabotTitleVersions(title) {
  const match = String(title || '').match(
    new RegExp(
      `^(?:update|bump)\\s+(.+?)(?:\\s+requirement)?\\s+from\\s+(.+?)\\s+to\\s+(.+?)(?:\\s+in\\s+\\/\\S+|\\s+in\\s+the\\s+.+?\\s+group)?\\s*$`,
      'i',
    ),
  );
  if (!match) return null;
  const packageName = match[1].trim();
  const fromVersion = cleanVersionToken(match[2]);
  const toVersion = cleanVersionToken(match[3]);
  if (!packageName || !fromVersion || !toVersion) return null;
  return { packageName, fromVersion, toVersion };
}

/** Text outside <details>, or null when the tags do not balance. */
function textOutsideDetails(text) {
  const tagRe = /<details\b[^>]*>|<\/details>/gi;
  let result = '';
  let last = 0;
  let depth = 0;
  let match;
  while ((match = tagRe.exec(text)) !== null) {
    if (depth === 0 && !match[0].toLowerCase().startsWith('<details')) return null;
    if (depth === 0) result += text.slice(last, match.index);
    if (match[0].toLowerCase().startsWith('<details')) depth += 1;
    else depth -= 1;
    if (depth < 0) return null;
    if (depth === 0) last = tagRe.lastIndex;
  }
  if (depth !== 0) return null;
  return result + text.slice(last);
}

const UPDATES_LINE = new RegExp(
  `^Updates\\s+\`([^\`]+)\`\\s+from\\s+(${VERSION_CLAUSE})\\s+to\\s+(${VERSION_CLAUSE})(?:\\s+.*)?$`,
  'i',
);

/**
 * Complete package/target pairs, or null when the upgrade is unknown.
 * A partial set is not returned: unknown fails open and runs the review.
 */
function upgradeIdentity(title, body) {
  const titled = dependabotTitleVersions(title);
  if (titled) return [{ packageName: titled.packageName, toVersion: titled.toVersion }];

  const visible = textOutsideDetails(body || '');
  if (visible === null) return null;
  const pairs = [];
  for (const line of visible.split('\n')) {
    const trimmed = line.trim();
    if (!/^Updates\b/i.test(trimmed)) continue;
    const match = UPDATES_LINE.exec(trimmed);
    if (!match) return null;
    const packageName = match[1].trim();
    const toVersion = cleanVersionToken(match[3]);
    if (!packageName || !toVersion) return null;
    pairs.push({ packageName, toVersion });
  }
  if (pairs.length === 0) return null;
  return pairs;
}

/** One-line comment marker for this upgrade, or '' when the upgrade is unknown. */
function reviewMarkerForUpgrade(title, body) {
  const pairs = upgradeIdentity(title, body);
  if (!pairs) return '';
  const canonical = Array.from(new Set(pairs.map((pair) => `${pair.packageName}\t${pair.toVersion}`)))
    .sort()
    .join('\n');
  return `<!-- cursor-dependabot-review ${Buffer.from(canonical, 'utf8').toString('base64')} -->`;
}

function commentFirstLine(body) {
  if (typeof body !== 'string') return '';
  const end = body.indexOf('\n');
  return (end === -1 ? body : body.slice(0, end)).trim();
}

function isActionsBotMarkerComment(comment) {
  if (comment?.user?.login !== ACTIONS_BOT_LOGIN) return false;
  const line = commentFirstLine(comment.body);
  return line === LEGACY_REVIEW_MARKER || /^<!-- cursor-dependabot-review \S+ -->$/.test(line);
}

function isActionsBotUpgradeReview(comment, marker) {
  return Boolean(marker) && comment?.user?.login === ACTIONS_BOT_LOGIN && commentFirstLine(comment.body) === marker;
}

async function runDependabotContext({ core }) {
  const body = process.env.PR_BODY || '';
  const title = process.env.PR_TITLE || '';
  const prNumber = Number(process.env.PR_NUMBER || '0');
  const parsed = parseDependencyUpdate(title, body);

  if (!parsed.upstreamRepo) {
    core.setFailed('PR body is missing an upstream GitHub repository link.');
    return;
  }

  const normalizedReleaseNotes = parsed.releaseNotes || 'PR body did not include a Release notes details section.';
  const normalizedCommits = parsed.commits || 'PR body did not include a Commits details section.';

  const out = {
    prNumber,
    upstreamRepo: parsed.upstreamRepo,
    packageName: parsed.packageName,
    fromVersion: parsed.fromVersion,
    toVersion: parsed.toVersion,
    releaseNotes: normalizedReleaseNotes,
    commits: normalizedCommits,
  };
  fs.writeFileSync('dependabot_comment_context.json', JSON.stringify(out, null, 2));
  fs.writeFileSync('dependabot_release_notes.md', normalizedReleaseNotes);
  fs.writeFileSync('dependabot_commits.md', normalizedCommits);
  core.setOutput('upstream_repo', parsed.upstreamRepo);
  core.setOutput('package_name', parsed.packageName);
  core.setOutput('from_version', parsed.fromVersion);
  core.setOutput('to_version', parsed.toVersion);
}

module.exports = runDependabotContext;
module.exports.parseDependencyUpdate = parseDependencyUpdate;
module.exports.reviewMarkerForUpgrade = reviewMarkerForUpgrade;
module.exports.isActionsBotMarkerComment = isActionsBotMarkerComment;
module.exports.isActionsBotUpgradeReview = isActionsBotUpgradeReview;
module.exports.LEGACY_REVIEW_MARKER = LEGACY_REVIEW_MARKER;
