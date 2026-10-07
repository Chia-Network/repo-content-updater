'use strict';

const fs = require('fs');

// Marker helpers live next to the PR parser so the trusted skip check and the
// comment poster share one upgrade identity. The target-PR step passes that
// identity to the poster as a single-line base64 output.

const REVIEW_MARKER_PREFIX = '<!-- cursor-dependabot-review';
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

function stripDetailsBlocks(text) {
  const tagRe = /<details\b[^>]*>|<\/details>/gi;
  let result = '';
  let last = 0;
  let depth = 0;
  let match;
  while ((match = tagRe.exec(text)) !== null) {
    if (depth === 0) result += text.slice(last, match.index);
    if (match[0].toLowerCase().startsWith('<details')) {
      depth += 1;
    } else {
      depth = Math.max(0, depth - 1);
    }
    if (depth === 0) last = tagRe.lastIndex;
  }
  if (depth === 0) result += text.slice(last);
  return result;
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

  const titleMatch =
    title.match(/[Uu]pdate\s+(.+?)\s+requirement\s+from\s+([^\s]+)\s+to\s+([^\s]+)/) ||
    title.match(/[Bb]ump\s+(.+?)\s+from\s+([^\s]+)\s+to\s+([^\s]+)/) ||
    title.match(/[Uu]pdate\s+(.+?)\s+from\s+([^\s]+)\s+to\s+([^\s]+)/);
  const renovateTitleMatch =
    !titleMatch &&
    (title.match(/(?:update|pin)\s+dependency\s+(.+?)\s+to\s+v?([^\s]+)/i) ||
      title.match(/(?:update|pin)\s+(.+?)\s+(?:action|digest|docker\s+tag)\s+to\s+v?([^\s]+)/i) ||
      title.match(/(?:update|pin)\s+(.+?)\s+to\s+v?([^\s]+)/i));

  let packageName;
  let fromVersion;
  let toVersion;
  if (titleMatch) {
    packageName = titleMatch[1].trim();
    fromVersion = titleMatch[2].trim();
    toVersion = titleMatch[3].trim();
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

function extractExplicitUpdates(body) {
  const outsideNotes = stripDetailsBlocks(body || '');
  const pairs = [];
  const re = /Updates\s+`([^`]+)`\s+from\s+(\S+)\s+to\s+(\S+)/gi;
  let match;
  while ((match = re.exec(outsideNotes)) !== null) {
    const packageName = match[1].trim();
    const toVersion = cleanVersionToken(match[3]);
    if (packageName && toVersion) pairs.push({ packageName, toVersion });
  }
  return pairs;
}

function extractTableBumps(body) {
  const outsideNotes = stripDetailsBlocks(body || '');
  if (!/\|\s*Package\s*\|\s*From\s*\|\s*To\s*\|/i.test(outsideNotes)) return [];
  const pairs = [];
  const re = /^\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|/gm;
  let match;
  while ((match = re.exec(outsideNotes)) !== null) {
    const packageName = match[1].trim();
    const toVersion = cleanVersionToken(match[3]);
    if (!packageName || !toVersion) continue;
    if (/^package$/i.test(packageName)) continue;
    if (/^:?-+:?$/.test(packageName)) continue;
    pairs.push({ packageName, toVersion });
  }
  return pairs;
}

/**
 * Stable id for one Dependabot upgrade. Rebases change head SHAs and the
 * commit list inside the PR body; those must not change this id. A new target
 * version must. Empty string means "unknown" — callers should review again.
 */
function upgradeIdentity(title, body) {
  const parsed = parseDependencyUpdate(title || '', body || '');
  const explicit = extractExplicitUpdates(body || '');
  let pairs = [];
  // Group updates list every package in the body. A title that names only one
  // package must not hide the rest of that list. A normal single-dependency PR
  // has no "Updates `pkg` from … to …" lines, so the title is the identity.
  if (explicit.length > 1) {
    pairs = explicit;
  } else if (parsed.packageName && parsed.toVersion) {
    pairs = [{ packageName: parsed.packageName, toVersion: cleanVersionToken(parsed.toVersion) }];
  } else if (explicit.length === 1) {
    pairs = explicit;
  } else {
    pairs = extractTableBumps(body || '');
  }
  if (pairs.length === 0) return '';
  const unique = new Set(pairs.map((pair) => `${pair.packageName}\n${pair.toVersion}`));
  return Array.from(unique).sort().join('\n---\n');
}

function reviewMarkerForIdentity(identity) {
  if (!identity) return LEGACY_REVIEW_MARKER;
  const encoded = Buffer.from(identity, 'utf8').toString('base64');
  return `<!-- cursor-dependabot-review ${encoded} -->`;
}

function commentHasReviewMarker(body) {
  return typeof body === 'string' && body.includes(REVIEW_MARKER_PREFIX);
}

function commentMatchesIdentity(body, identity) {
  if (!identity || typeof body !== 'string') return false;
  return body.includes(reviewMarkerForIdentity(identity));
}

function isActionsBotUpgradeReview(comment, identity) {
  return comment?.user?.login === ACTIONS_BOT_LOGIN && commentMatchesIdentity(comment?.body, identity);
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
module.exports.upgradeIdentity = upgradeIdentity;
module.exports.reviewMarkerForIdentity = reviewMarkerForIdentity;
module.exports.commentHasReviewMarker = commentHasReviewMarker;
module.exports.commentMatchesIdentity = commentMatchesIdentity;
module.exports.isActionsBotUpgradeReview = isActionsBotUpgradeReview;
module.exports.ACTIONS_BOT_LOGIN = ACTIONS_BOT_LOGIN;
module.exports.LEGACY_REVIEW_MARKER = LEGACY_REVIEW_MARKER;
