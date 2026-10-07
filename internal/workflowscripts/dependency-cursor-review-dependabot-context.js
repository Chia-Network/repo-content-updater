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

// actions/github-script does not ship a YAML library. This accepts only the flat
// Dependabot trailer and returns null on anything else.
const DEPENDENCY_KEYS = new Set([
  'dependency-name',
  'dependency-version',
  'dependency-type',
  'update-type',
  'dependency-group',
  'directory',
]);

function parseScalar(raw) {
  if (raw == null) return null;
  const value = String(raw);
  if (value !== value.trim() || value.includes('\n')) return null;
  if (value === '') return '';
  const quote = value[0];
  if (quote === '"' || quote === "'") {
    if (value.length < 2 || value[value.length - 1] !== quote) return null;
    const inner = value.slice(1, -1);
    if (inner.includes('\\') || inner.includes(quote)) return null;
    return inner;
  }
  if (!/^[A-Za-z0-9./][A-Za-z0-9._+\-/:]*$/.test(value)) return null;
  return value;
}

function metadataBlocks(message) {
  if (typeof message !== 'string' || message.includes('\0')) return null;
  const lines = message.split(/\r?\n/);
  const blocks = [];
  let start = -1;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (line === '---') {
      if (start !== -1) return null;
      start = index;
    } else if (line === '...') {
      if (start === -1) return null;
      blocks.push(lines.slice(start + 1, index));
      start = -1;
    }
  }
  if (start !== -1) return null;
  return blocks;
}

function parseUpdatedDependencies(lines) {
  if (!Array.isArray(lines) || lines.length === 0 || lines[0] !== 'updated-dependencies:') return null;
  const entries = [];
  let current = null;
  const finish = (entry) => {
    const name = entry['dependency-name'];
    const version = entry['dependency-version'];
    if (!name || !version) return null;
    const directory = entry.directory || '';
    return directory ? `${name}\t${version}\t${directory}` : `${name}\t${version}`;
  };
  for (const line of lines.slice(1)) {
    if (line !== line.trimEnd() || line === '') return null;
    const item = line.match(/^- ([a-z][a-z0-9-]*):(?: (.*))?$/);
    const field = line.match(/^  ([a-z][a-z0-9-]*):(?: (.*))?$/);
    const match = item || field;
    if (!match || !DEPENDENCY_KEYS.has(match[1])) return null;
    if (field && !current) return null;
    if (item && current) {
      const pair = finish(current);
      if (!pair) return null;
      entries.push(pair);
      current = null;
    }
    if (!current) current = {};
    if (Object.prototype.hasOwnProperty.call(current, match[1])) return null;
    const scalar = parseScalar(match[2] == null ? '' : match[2]);
    if (scalar == null) return null;
    current[match[1]] = scalar;
  }
  if (!current) return null;
  const pair = finish(current);
  if (!pair) return null;
  entries.push(pair);
  return entries;
}

/**
 * Identity for verified Dependabot commit messages.
 * Every message must contain one trailer. The marker is the sorted union of
 * name, version, and directory (only when the trailer has directory). Exact
 * duplicate rows collapse. A missing or malformed trailer returns ''.
 * Directory is not inferred from the branch name.
 */
function reviewMarkerFromCommitMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0) return '';
  const pairs = [];
  for (const message of messages) {
    const blocks = metadataBlocks(message);
    if (!blocks || blocks.length !== 1) return '';
    const entries = parseUpdatedDependencies(blocks[0]);
    if (!entries || entries.length === 0) return '';
    pairs.push(...entries);
  }
  const canonical = Array.from(new Set(pairs)).sort().join('\n');
  if (!canonical) return '';
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
module.exports.reviewMarkerFromCommitMessages = reviewMarkerFromCommitMessages;
module.exports.isActionsBotMarkerComment = isActionsBotMarkerComment;
module.exports.isActionsBotUpgradeReview = isActionsBotUpgradeReview;
module.exports.LEGACY_REVIEW_MARKER = LEGACY_REVIEW_MARKER;
