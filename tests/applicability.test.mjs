// Fixture tests for the CVE applicability logic in poc/index.html.
// The code under test is loaded verbatim from between the @applicability markers,
// so these tests exercise exactly what ships. Run: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const html = fs.readFileSync(new URL('../poc/index.html', import.meta.url), 'utf8');
const source = html.match(/\/\/ @applicability-begin[^\n]*\n([\s\S]*?)\/\/ @applicability-end/)?.[1];
assert.ok(source, 'applicability markers not found in poc/index.html');
const ctx = { catalogVersions: [], catalogEdition: null };
vm.createContext(ctx);
vm.runInContext(`${source}\nthis.api = { cpeEdition, applicabilityMatches, vulnStatusFor };`, ctx);
const { cpeEdition, vulnStatusFor } = ctx.api;

const cpe = (swEdition, version = '*') => `cpe:2.3:a:gitlab:gitlab:${version}:*:*:*:${swEdition}:*:*:*`;
const range = (swEdition, startIncl, endExcl) => ({
  vulnerable: true, criteria: cpe(swEdition),
  versionStartIncluding: startIncl, versionStartExcluding: null,
  versionEndIncluding: null, versionEndExcluding: endExcl,
});
const cve = (...applicability) => ({ id: 'CVE-TEST', applicability });
const status = (item, versions, edition) => {
  const { status: s, editionDependent } = vulnStatusFor(item, versions, edition);
  return editionDependent ? `${s}:edition` : s;
};

test('cpeEdition reads the sw_edition field (segment 9), as NVD records GitLab CE/EE', () => {
  assert.equal(cpeEdition(cpe('enterprise')), 'enterprise');
  assert.equal(cpeEdition(cpe('community')), 'community');
  assert.equal(cpeEdition(cpe('*')), '*');
  assert.equal(cpeEdition('cpe:2.3:a:gitlab:gitlab:*:*:*'), '*'); // truncated string
});

test('EE-only CVE: vulnerable on EE, not applicable on CE', () => {
  const item = cve(range('enterprise', '17.0.0', '17.5.2'));
  assert.equal(status(item, ['17.4.0'], 'enterprise'), 'vulnerable');
  assert.equal(status(item, ['17.4.0'], 'community'), 'fixed');
});

test('CE entry also applies to EE (EE contains all CE code)', () => {
  const item = cve(range('community', '17.0.0', '17.5.2'));
  assert.equal(status(item, ['17.4.0'], 'community'), 'vulnerable');
  assert.equal(status(item, ['17.4.0'], 'enterprise'), 'vulnerable');
});

test('EE range lagging the CE range does not produce a false fixed on EE (CVE-2022-2250 shape)', () => {
  const item = cve(range('community', '11.1.0', '14.10.5'), range('enterprise', '11.1.0', '14.0.5'));
  assert.equal(status(item, ['14.5.0'], 'enterprise'), 'vulnerable');
  assert.equal(status(item, ['14.5.0'], 'community'), 'vulnerable');
});

test('wildcard and NA editions apply to both editions', () => {
  for (const sw of ['*', '-']) {
    const item = cve(range(sw, '17.0.0', '17.5.2'));
    assert.equal(status(item, ['17.4.0'], 'community'), 'vulnerable');
    assert.equal(status(item, ['17.4.0'], 'enterprise'), 'vulnerable');
  }
});

test('unknown edition: an edition-specific CVE is indeterminate, never guessed', () => {
  const eeOnly = cve(range('enterprise', '17.0.0', '17.5.2'));
  const ceOnly = cve(range('community', '17.0.0', '17.5.2'));
  assert.equal(status(eeOnly, ['17.4.0'], null), 'indeterminate:edition');
  assert.equal(status(ceOnly, ['17.4.0'], null), 'vulnerable'); // CE entries cover both editions
  assert.equal(status(eeOnly, ['17.4.0'], 'not-an-edition'), 'indeterminate:edition');
});

test('unknown edition: a CVE listed for both editions stays definite', () => {
  const both = cve(range('community', '17.0.0', '17.5.2'), range('enterprise', '17.0.0', '17.5.2'));
  assert.equal(status(both, ['17.4.0'], null), 'vulnerable');
  assert.equal(status(both, ['17.6.0'], null), 'fixed');
});

test('version boundaries are respected per edition', () => {
  const item = cve(range('enterprise', '17.0.0', '17.5.2'));
  assert.equal(status(item, ['17.5.2'], 'enterprise'), 'fixed');      // end excluded
  assert.equal(status(item, ['17.0.0'], 'enterprise'), 'vulnerable'); // start included
  assert.equal(status(item, ['16.11.9'], 'enterprise'), 'fixed');
});

test('patch range straddling a fix is indeterminate, and not flagged as edition-dependent', () => {
  const item = cve(range('enterprise', '17.0.0', '17.5.2'));
  assert.equal(status(item, ['17.5.1', '17.5.2', '17.5.3'], 'enterprise'), 'indeterminate');
});

test('vulnerable:false entries never match', () => {
  const item = cve({ ...range('*', '17.0.0', '17.5.2'), vulnerable: false });
  assert.equal(status(item, ['17.4.0'], 'enterprise'), 'fixed');
});

test('exact-version CPEs match only that version and edition', () => {
  const item = cve({ vulnerable: true, criteria: cpe('enterprise', '19.5.0') });
  assert.equal(status(item, ['19.5.0'], 'enterprise'), 'vulnerable');
  assert.equal(status(item, ['19.5.1'], 'enterprise'), 'fixed');
  assert.equal(status(item, ['19.5.0'], 'community'), 'fixed');
});

test('real catalogue: every errata record keeps its NVD original and a cited reason', () => {
  const catalog = JSON.parse(fs.readFileSync(new URL('../poc/cves/gitlab-10.0.0-and-later.json', import.meta.url), 'utf8'));
  const fixed = catalog.vulnerabilities.filter((item) => item.errata);
  assert.ok(fixed.length >= 9);
  for (const item of fixed) {
    assert.ok(Array.isArray(item.errata.nvdApplicability) && item.errata.nvdApplicability.length, item.id);
    assert.ok(item.errata.notes.length, item.id);
  }
  const byId = new Map(catalog.vulnerabilities.map((item) => [item.id, item]));
  // CVE-2024-7047: NVD said exact 7.2.0; the advisory says 17.2 before 17.2.1.
  assert.equal(vulnStatusFor(byId.get('CVE-2024-7047'), ['17.2.0'], 'community').status, 'vulnerable');
  // CVE-2024-4201: NVD typo 16.111.4; 16.11.5 is fixed.
  assert.equal(vulnStatusFor(byId.get('CVE-2024-4201'), ['16.11.5'], 'community').status, 'fixed');
  // No agent-only review may claim confirmed-compatible.
  assert.equal(catalog.vulnerabilities.filter((i) =>
    i.browserApiAssessment.status === 'confirmed-compatible' && !i.browserApiAssessment.manuallyReviewed).length, 0);
});

test('real catalogue: EE-only records surface on EE builds and stay off CE builds', () => {
  const catalog = JSON.parse(fs.readFileSync(new URL('../poc/cves/gitlab-10.0.0-and-later.json', import.meta.url), 'utf8'));
  const eeOnly = catalog.vulnerabilities.filter((item) => {
    const eds = new Set((item.applicability || []).map((e) => cpeEdition(e.criteria)));
    return eds.size === 1 && eds.has('enterprise');
  });
  assert.ok(eeOnly.length > 100, `expected many EE-only records, got ${eeOnly.length}`);
  const v = '16.0.0';
  const onEe = eeOnly.filter((item) => vulnStatusFor(item, [v], 'enterprise').status === 'vulnerable').length;
  const onCe = eeOnly.filter((item) => vulnStatusFor(item, [v], 'community').status !== 'fixed').length;
  assert.ok(onEe > 0, 'EE-only CVEs must apply to an EE build');
  assert.equal(onCe, 0, 'EE-only CVEs must never apply to a CE build');
});
