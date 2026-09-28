'use strict';

const fs = require('fs');

module.exports = async function runPostComment({ github, context, core }) {
  const marker = '<!-- cursor-dependabot-review -->';
  const analysisMaxLen = 48000;
  const malwareMaxLen = 10000;
  const githubCommentLimit = 65536;
  const malwareScanStatus = process.env.MALWARE_SCAN_STATUS || '';
  const malwareScanChangedCount = process.env.MALWARE_SCAN_CHANGED_COUNT || '';
  const malwareScanSummaryOutput = process.env.MALWARE_SCAN_SUMMARY || '';
  const issueNumber = Number(process.env.PR_NUMBER || '0');

  function readText(path, fallback = '') {
    try {
      return fs.readFileSync(path, 'utf8');
    } catch (_) {
      return fallback;
    }
  }

  const raw = readText('cursor_output.json', '{"result":"No Cursor output generated."}');
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (_) {
    parsed = { result: raw };
  }

  const analysis =
    parsed.result ||
    parsed.output ||
    parsed.text ||
    parsed.message ||
    raw;
  const analysisText =
    typeof analysis === 'string'
      ? analysis
      : JSON.stringify(analysis, null, 2) || String(analysis);
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
    [
      marker,
      '## 🤖 Cursor Dependency Analysis',
      '',
      analysisPart,
      '',
      '---',
      '',
      malwarePart,
    ].join('\n');
  let body = renderBody(trimmedAnalysis, trimmedMalware);
  if (body.length > githubCommentLimit) {
    const allowedAnalysis = Math.max(
      0,
      analysisMaxLen - (body.length - githubCommentLimit) - 256
    );
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
    .filter((c) => typeof c.body === 'string' && c.body.includes(marker))
    .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
  const latestMarker =
    markerComments.length > 0 ? markerComments[markerComments.length - 1] : null;

  const hasNonManagedCommentaryAfterLatest =
    latestMarker &&
    comments.some(
      (c) =>
        c.id !== latestMarker.id &&
        !(typeof c.body === 'string' && c.body.includes(marker)) &&
        new Date(c.created_at).getTime() > new Date(latestMarker.created_at).getTime()
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
};
