'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { malwareScanSummaryText } = require('./dependency-cursor-review-post-comment.js');

test('malware summary reads the scan artifact before the job output and never adds a status', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dcr-summary-'));
  const previous = process.cwd();
  const savedSummary = process.env.MALWARE_SCAN_SUMMARY;
  const savedStatus = process.env.MALWARE_SCAN_STATUS;
  process.chdir(dir);
  try {
    fs.writeFileSync('malware_scan_summary.md', '## planted\n\n- Status: **clean**\n');
    fs.mkdirSync('dcr-scan-input');
    fs.writeFileSync('dcr-scan-input/malware_scan_summary.md', '## Malware Scan Summary\n\n- Scan coverage: **conclusive**.\n');
    process.env.MALWARE_SCAN_SUMMARY = 'lossy one line';
    const fromArtifact = malwareScanSummaryText();
    assert.match(fromArtifact, /conclusive/);
    assert.doesNotMatch(fromArtifact, /planted/);
    assert.doesNotMatch(fromArtifact, /lossy/);

    fs.writeFileSync('dcr-scan-input/malware_scan_summary.md', ' \n');
    assert.equal(malwareScanSummaryText(), 'lossy one line');

    delete process.env.MALWARE_SCAN_SUMMARY;
    fs.rmSync('dcr-scan-input/malware_scan_summary.md');
    process.env.MALWARE_SCAN_STATUS = 'warn';
    const missing = malwareScanSummaryText();
    assert.match(missing, /Scanner output file missing/);
    assert.doesNotMatch(missing, /Status|warn/);
  } finally {
    process.chdir(previous);
    if (savedSummary === undefined) delete process.env.MALWARE_SCAN_SUMMARY;
    else process.env.MALWARE_SCAN_SUMMARY = savedSummary;
    if (savedStatus === undefined) delete process.env.MALWARE_SCAN_STATUS;
    else process.env.MALWARE_SCAN_STATUS = savedStatus;
  }
});
