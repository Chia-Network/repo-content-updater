'use strict';

const fs = require('fs');

const {
  ACTIONS_BOT_LOGIN,
  commentHasReviewMarker,
  reviewMarkerForIdentity,
} = require('./dependency-cursor-review-dependabot-context.js');

function readText(path, fallback = '') {
  try {
    return fs.readFileSync(path, 'utf8');
  } catch (_) {
    return fallback;
  }
}

function analysisTextFromRaw(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (_) {
    parsed = { result: raw };
  }
  const analysis = parsed.result || parsed.output || parsed.text || parsed.message || raw;
  return typeof analysis === 'string' ? analysis : JSON.stringify(analysis, null, 2) || String(analysis);
}

function analysisIsComplete(raw) {
  const text = analysisTextFromRaw(raw);
  if (!text.trim()) return false;
  if (text.includes('CURSOR_API_KEY is not set')) return false;
  if (text.includes('No Cursor output generated.')) return false;
  return true;
}

function decodeUpgradeIdentity(encoded) {
  if (!encoded) return '';
  return Buffer.from(String(encoded), 'base64').toString('utf8');
}

/**
 * Stamp a versioned marker only after a real analysis. A missing API key still
 * posts a comment, but that comment must not suppress the next push.
 */
function selectPostedMarker(identity, raw) {
  if (!identity || !analysisIsComplete(raw)) return reviewMarkerForIdentity('');
  return reviewMarkerForIdentity(identity);
}

async function runPostComment({ github, context, core }) {
  const analysisMaxLen = 48000;
  const malwareMaxLen = 10000;
  const githubCommentLimit = 65536;
  const malwareScanStatus = process.env.MALWARE_SCAN_STATUS || '';
  const malwareScanChangedCount = process.env.MALWARE_SCAN_CHANGED_COUNT || '';
  const malwareScanSummaryOutput = process.env.MALWARE_SCAN_SUMMARY || '';
  const issueNumber = Number(process.env.PR_NUMBER || '0');
  const identity = decodeUpgradeIdentity(process.env.UPGRADE_IDENTITY || '');

  const raw = readText('cursor_output.json', '{"result":"No Cursor output generated."}');
  const analysisText = analysisTextFromRaw(raw);
  const marker = selectPostedMarker(identity, raw);
  const malwareSummaryFallback =
    (typeof malwareScanSummaryOutput === 'string' && malwareScanSummaryOutput.trim()) ||
    [
      '## Malware Scan Summary',
      '',
      `- Status: **${malwareScanStatus || 'unknown'}**`,
      `- Changed upstream files scanned: \`${malwareScanChangedCount || 'unknown'}\``,
      '- Scanner output file missing.',
    ].join('\n');
  const malwareSummary = readText('malware_scan_summary.md', malwareSummaryFallback);

  let trimmedAnalysis = analysisText.slice(0, analysisMaxLen);
  let trimmedMalware = malwareSummary.slice(0, malwareMaxLen);
  const renderBody = (analysisPart, malwarePart) =>
    [marker, '## 🤖 Cursor Dependency Analysis', '', analysisPart, '', '---', '', malwarePart].join('\n');
  let body = renderBody(trimmedAnalysis, trimmedMalware);
  if (body.length > githubCommentLimit) {
    const allowedAnalysis = Math.max(0, analysisMaxLen - (body.length - githubCommentLimit) - 256);
    trimmedAnalysis = analysisText.slice(0, allowedAnalysis);
    body = renderBody(trimmedAnalysis, trimmedMalware);
  }

  const { owner, repo } = context.repo;
  const comments = await github.paginate(github.rest.issues.listComments, {
    owner,
    repo,
    issue_number: issueNumber,
    per_page: 100,
  });
  const markerComments = comments
    .filter((comment) => comment.user?.login === ACTIONS_BOT_LOGIN && commentHasReviewMarker(comment.body))
    .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
  const latestMarker = markerComments.length > 0 ? markerComments[markerComments.length - 1] : null;

  const hasNonManagedCommentaryAfterLatest =
    latestMarker &&
    comments.some(
      (comment) =>
        comment.id !== latestMarker.id &&
        !commentHasReviewMarker(comment.body) &&
        new Date(comment.created_at).getTime() > new Date(latestMarker.created_at).getTime(),
    );

  if (latestMarker && !hasNonManagedCommentaryAfterLatest) {
    await github.rest.issues.updateComment({
      owner,
      repo,
      comment_id: latestMarker.id,
      body,
    });
  } else {
    await github.rest.issues.createComment({
      owner,
      repo,
      issue_number: issueNumber,
      body,
    });
  }
  if (typeof core?.info === 'function') {
    core.info(
      identity && marker !== reviewMarkerForIdentity('')
        ? 'Posted Dependabot review marker for this dependency upgrade.'
        : 'Posted dependency review comment without an upgrade identity marker.',
    );
  }
}

module.exports = runPostComment;
module.exports.selectPostedMarker = selectPostedMarker;
module.exports.decodeUpgradeIdentity = decodeUpgradeIdentity;
