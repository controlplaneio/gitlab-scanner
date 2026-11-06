#!/usr/bin/env node

import fs from 'node:fs';

const args = process.argv.slice(2);
const input = args.find((arg) => !arg.startsWith('--')) || 'poc/cves/gitlab-10.0.0-and-later.json';
const requireUncertainXdb = args.includes('--require-xdb-uncertain');
const requireCompleteXdb = args.includes('--require-xdb-complete');
const requireReviewedXdb = args.includes('--require-xdb-reviews');
const catalog = JSON.parse(fs.readFileSync(input, 'utf8'));
const errors = [];
const warnings = [];

const fail = (message) => errors.push(message);
const warn = (message) => warnings.push(message);
const values = catalog.vulnerabilities;
const allowedStatuses = new Set([
  'confirmed-compatible',
  'likely-compatible',
  'conditional-compatible',
  'unresolved',
  'outside-threat-model',
]);

if (!Array.isArray(values) || !values.length) fail('vulnerabilities must be a non-empty array');
if (catalog.catalogScope !== 'GitLab versions 10.0.0 and later') fail('catalogScope is not the master-catalog scope');
if (catalog.minimumVersion !== '10.0.0') fail('minimumVersion must be 10.0.0');
if (catalog.detectedVersion !== null) fail('master catalogue detectedVersion must be null');

const ids = new Set();
for (const [index, item] of values.entries()) {
  const at = `vulnerabilities[${index}] ${item.id || '(missing id)'}`;
  if (!/^CVE-\d{4}-\d{4,}$/.test(item.id || '')) fail(`${at}: malformed CVE id`);
  if (ids.has(item.id)) fail(`${at}: duplicate CVE id`);
  ids.add(item.id);
  if (!item.published || Number.isNaN(Date.parse(item.published))) fail(`${at}: invalid published date`);
  if (item.published < '2017-09-22') fail(`${at}: predates the GitLab 10.0.0 catalogue floor`);
  if (!item.summary || typeof item.summary !== 'string') fail(`${at}: missing summary`);
  if (!item.cvss || !Object.hasOwn(item.cvss, 'severity')) fail(`${at}: missing CVSS data contract`);
  if (!item.links?.nvd || !item.links?.cve || !Array.isArray(item.links?.gitlab)) fail(`${at}: incomplete links contract`);
  if (!Array.isArray(item.applicability) || !item.applicability.length) {
    fail(`${at}: missing GitLab applicability entries`);
  } else {
    for (const [rangeIndex, range] of item.applicability.entries()) {
      const rangeAt = `${at} applicability[${rangeIndex}]`;
      if (range.vulnerable !== true) fail(`${rangeAt}: non-vulnerable CPE entry retained`);
      if (!range.criteria?.startsWith('cpe:2.3:a:gitlab:gitlab:')) fail(`${rangeAt}: non-GitLab product CPE`);
      if (range.versionStartIncluding && range.versionStartExcluding) fail(`${rangeAt}: both inclusive and exclusive starts set`);
      if (range.versionEndIncluding && range.versionEndExcluding) fail(`${rangeAt}: both inclusive and exclusive ends set`);
    }
  }
  const assessment = item.browserApiAssessment;
  if (!assessment || !allowedStatuses.has(assessment.status)) fail(`${at}: invalid browserApiAssessment status`);
  if (!assessment?.rationale || !assessment?.likelihood) fail(`${at}: incomplete browserApiAssessment data contract`);
  const xdb = item.vulnCheckXdb;
  if (xdb) {
    const expected = `https://www.vulncheck.com/api/xdb/?cve=${encodeURIComponent(item.id)}`;
    if (xdb.queryUrl !== expected) fail(`${at}: unexpected XDB query URL`);
    if (!Array.isArray(xdb.matches)) fail(`${at}: XDB matches is not an array`);
    for (const match of xdb.matches || []) {
      if (!match.id || !match.url) fail(`${at}: XDB match lacks id or URL`);
      if (!match.sourceReview?.reviewedAt) warn(`${at}: XDB match ${match.id || '(missing id)'} has no source review`);
    }
  }
}

for (let index = 1; index < values.length; index += 1) {
  const previous = values[index - 1];
  const current = values[index];
  const order = Date.parse(previous.published) - Date.parse(current.published);
  if (order < 0 || (order === 0 && previous.id.localeCompare(current.id) < 0)) {
    fail(`catalogue is not sorted newest-first at ${previous.id}/${current.id}`);
    break;
  }
}

const counts = Object.groupBy(values, (item) => item.browserApiAssessment.status);
const expectedSummary = Object.fromEntries(Object.entries(counts).map(([status, items]) => [status, items.length]));
const actualSummary = Object.fromEntries((catalog.assessmentSummary || []).map(({ status, count }) => [status, count]));
const summaryKeys = new Set([...Object.keys(expectedSummary), ...Object.keys(actualSummary)]);
if ([...summaryKeys].some((key) => expectedSummary[key] !== actualSummary[key])) fail('assessmentSummary does not match record statuses');
for (const item of values) {
  if (item.browserApiAssessment.status === 'confirmed-compatible' && !item.browserApiAssessment.manuallyReviewed) {
    fail(`${item.id} is confirmed-compatible without manual review`);
  }
}

const expectedCoverage = {
  totalRecords: values.length,
  manuallyReviewedRecords: values.filter((item) => item.browserApiAssessment.manuallyReviewed).length,
  parallelAgentReviewedRecords: values.filter((item) => item.browserApiAssessment.reviewMode === 'parallel-agent-review').length,
  applicabilityErrataRecords: values.filter((item) => item.errata).length,
  structuredThreatModelExclusions: values.filter((item) => item.browserApiAssessment.reviewMode === 'structured-threat-model-exclusion').length,
  publicPrimaryReproductionsReviewed: values.filter((item) => item.browserApiAssessment.pocEvidenceState === 'public-primary-reproduction-reviewed').length,
  privateOrUnavailablePrimaryDetails: values.filter((item) => item.browserApiAssessment.pocEvidenceState === 'primary-details-private-or-not-publicly-retrievable').length,
  unresolvedRecords: values.filter((item) => item.browserApiAssessment.status === 'unresolved').length,
  pendingManualCandidateReviews: values.filter((item) => item.browserApiAssessment.status !== 'outside-threat-model' && !item.browserApiAssessment.manuallyReviewed).length,
  xdbRecordsChecked: values.filter((item) => item.vulnCheckXdb?.checkedAt).length,
  xdbRecordsWithMatches: values.filter((item) => item.vulnCheckXdb?.matches?.length).length,
  xdbRepositoriesFound: values.reduce((sum, item) => sum + (item.vulnCheckXdb?.matches?.length || 0), 0),
  xdbRepositoriesSourceReviewed: values.reduce((sum, item) => sum + (item.vulnCheckXdb?.matches || []).filter((match) => match.sourceReview?.reviewedAt).length, 0),
};
for (const [key, expected] of Object.entries(expectedCoverage)) {
  if (catalog.assessmentCoverage?.[key] !== expected) fail(`assessmentCoverage.${key} is ${catalog.assessmentCoverage?.[key]}, expected ${expected}`);
}

const unresolved = values.filter((item) => item.browserApiAssessment.status === 'unresolved');
const unresolvedWithoutXdb = unresolved.filter((item) => !item.vulnCheckXdb?.checkedAt);
if (unresolvedWithoutXdb.length) {
  const message = `${unresolvedWithoutXdb.length}/${unresolved.length} unresolved records lack an XDB result`;
  if (requireUncertainXdb) fail(message); else warn(message);
}

const withoutXdb = values.filter((item) => !item.vulnCheckXdb?.checkedAt);
if (withoutXdb.length) {
  const message = `${withoutXdb.length}/${values.length} records lack an XDB result`;
  if (requireCompleteXdb) fail(message); else warn(message);
}

const xdbRepositoriesWithoutSourceReview = values.reduce((sum, item) =>
  sum + (item.vulnCheckXdb?.matches || []).filter((match) => !match.sourceReview?.reviewedAt).length, 0);
if (xdbRepositoriesWithoutSourceReview) {
  const message = `${xdbRepositoriesWithoutSourceReview} XDB repository matches lack a source review`;
  if (requireReviewedXdb) fail(message); else warn(message);
}

const report = {
  file: input,
  records: values.length,
  uniqueIds: ids.size,
  statusCounts: expectedSummary,
  applicabilityEntries: values.reduce((sum, item) => sum + (item.applicability?.length || 0), 0),
  unresolvedWithoutXdb: unresolvedWithoutXdb.length,
  xdbRecordsWithoutResult: withoutXdb.length,
  xdbRepositoriesWithoutSourceReview,
  warnings,
  errors,
};

console.log(JSON.stringify(report, null, 2));
if (errors.length) process.exitCode = 1;
