#!/usr/bin/env node
/*
 * Post-processing for the CVE catalogue, run after enrich-browser-api.mjs on every
 * refresh (update-cves.sh calls it). Idempotent: running it twice changes nothing.
 *
 *   1. Re-applies the agent-assisted reviews kept in poc/cves/agent-reviews.json, which
 *      enrich-browser-api.mjs would otherwise overwrite as unresolved.
 *   2. Enforces the evidence bar for 'confirmed-compatible': only a manually reviewed
 *      record may carry it. Agent-only reviews are capped at 'likely-compatible'.
 *   3. Applies poc/cves/errata.json: range corrections taken from GitLab's advisory
 *      text, and the EE-only edition rule. The NVD original is kept on the record.
 *   4. Recomputes assessmentSummary and assessmentCoverage from the records.
 *
 * Usage: node scripts/apply-catalogue-fixes.mjs [catalog.json]
 *        node scripts/apply-catalogue-fixes.mjs --capture-agent-reviews [catalog.json]
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const capture = args.includes('--capture-agent-reviews');
const catalogPath = args.find((a) => !a.startsWith('--')) || path.join(root, 'poc/cves/gitlab-10.0.0-and-later.json');
const reviewsPath = path.join(root, 'poc/cves/agent-reviews.json');
const errataPath = path.join(root, 'poc/cves/errata.json');

const catalog = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
const byId = new Map(catalog.vulnerabilities.map((item) => [item.id, item]));

// 1. Agent-assisted reviews.
if (capture) {
  const reviews = {};
  for (const item of catalog.vulnerabilities) {
    if (item.browserApiAssessment?.reviewMode === 'parallel-agent-review') reviews[item.id] = item.browserApiAssessment;
  }
  fs.writeFileSync(reviewsPath, JSON.stringify({
    description: 'Browser-path assessments made by agent-assisted primary-source review, not manual review and not browser reproduction. Merged back by scripts/apply-catalogue-fixes.mjs after enrich-browser-api.mjs.',
    reviews,
  }, null, 2) + '\n');
  console.log(`captured ${Object.keys(reviews).length} agent-assisted reviews to ${path.relative(root, reviewsPath)}`);
}
const agentReviews = fs.existsSync(reviewsPath) ? JSON.parse(fs.readFileSync(reviewsPath, 'utf8')).reviews : {};
for (const [id, assessment] of Object.entries(agentReviews)) {
  const item = byId.get(id);
  if (item) item.browserApiAssessment = { ...assessment };
}

// 2. Evidence bar for 'confirmed-compatible'.
const CAP_NOTE = 'Capped at likely-compatible: agent-assisted review only. Not manually reviewed and not reproduced from a browser.';
for (const item of catalog.vulnerabilities) {
  const a = item.browserApiAssessment;
  if (a?.status === 'confirmed-compatible' && !a.manuallyReviewed) {
    a.status = 'likely-compatible';
    a.likelihood = 'medium-high';
    a.evidenceNotes = [...new Set([...(a.evidenceNotes || []), CAP_NOTE])];
  }
}

// 3. Errata.
const errata = JSON.parse(fs.readFileSync(errataPath, 'utf8'));
const cpe = (edition) => `cpe:2.3:a:gitlab:gitlab:*:*:*:*:${edition}:*:*:*`;
const sw = (entry) => String(entry.criteria).split(':')[9] || '*';
const withEdition = (entry, edition) => {
  const parts = String(entry.criteria).split(':'); parts[9] = edition;
  return { ...entry, criteria: parts.join(':') };
};
const included = new RegExp(errata.eeOnlyRule.summaryMatches);
const excluded = new RegExp(errata.eeOnlyRule.summaryExcludes);
let rangeFixes = 0; let eeOnlyFixes = 0;
for (const item of catalog.vulnerabilities) {
  // Always start from the NVD original so a re-run is idempotent.
  const nvd = item.errata?.nvdApplicability || item.applicability;
  delete item.errata;
  item.applicability = nvd;
  const notes = [];
  const fix = errata.ranges[item.id];
  if (fix) {
    const editions = fix.edition === '*' ? ['*'] : [fix.edition];
    item.applicability = editions.flatMap((edition) => fix.ranges.map(([start, end]) => ({
      vulnerable: true, criteria: cpe(edition),
      versionStartIncluding: start, versionStartExcluding: null,
      versionEndIncluding: null, versionEndExcluding: end,
    })));
    notes.push(`${fix.reason} ${fix.source}`);
    rangeFixes += 1;
  }
  const summary = item.summary || '';
  if (included.test(summary) && !excluded.test(summary) &&
      item.applicability.some((entry) => ['community', '*', '-'].includes(sw(entry)))) {
    const seen = new Set();
    item.applicability = item.applicability
      .filter((entry) => sw(entry) !== 'community')
      .map((entry) => (['*', '-'].includes(sw(entry)) ? withEdition(entry, 'enterprise') : entry))
      .filter((entry) => { const k = JSON.stringify(entry); return seen.has(k) ? false : seen.add(k); });
    notes.push('GitLab\'s advisory scopes this to GitLab EE only, so CE entries in the NVD applicability were dropped.');
    eeOnlyFixes += 1;
  }
  if (notes.length) item.errata = { notes, nvdApplicability: nvd };
}

// 4. Summary and coverage, recomputed from the records.
const vs = catalog.vulnerabilities;
const order = ['confirmed-compatible', 'likely-compatible', 'conditional-compatible', 'unresolved', 'outside-threat-model'];
const counts = Object.groupBy(vs, (item) => item.browserApiAssessment.status);
catalog.assessmentSummary = Object.keys(counts)
  .sort((a, b) => (order.indexOf(a) + 1 || 99) - (order.indexOf(b) + 1 || 99))
  .map((status) => ({ status, count: counts[status].length }));
catalog.assessmentCoverage = {
  ...catalog.assessmentCoverage,
  totalRecords: vs.length,
  manuallyReviewedRecords: vs.filter((i) => i.browserApiAssessment.manuallyReviewed).length,
  parallelAgentReviewedRecords: vs.filter((i) => i.browserApiAssessment.reviewMode === 'parallel-agent-review').length,
  structuredThreatModelExclusions: vs.filter((i) => i.browserApiAssessment.reviewMode === 'structured-threat-model-exclusion').length,
  publicPrimaryReproductionsReviewed: vs.filter((i) => i.browserApiAssessment.pocEvidenceState === 'public-primary-reproduction-reviewed').length,
  privateOrUnavailablePrimaryDetails: vs.filter((i) => i.browserApiAssessment.pocEvidenceState === 'primary-details-private-or-not-publicly-retrievable').length,
  unresolvedRecords: vs.filter((i) => i.browserApiAssessment.status === 'unresolved').length,
  pendingManualCandidateReviews: vs.filter((i) =>
    i.browserApiAssessment.status !== 'outside-threat-model' && !i.browserApiAssessment.manuallyReviewed).length,
  applicabilityErrataRecords: vs.filter((i) => i.errata).length,
};

fs.writeFileSync(catalogPath, JSON.stringify(catalog, null, 2) + '\n');
console.log(JSON.stringify({ rangeFixes, eeOnlyFixes, summary: catalog.assessmentSummary, coverage: catalog.assessmentCoverage }));
