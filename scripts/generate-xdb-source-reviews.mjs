#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';

const [catalogFile, repositoriesDir, outputFile] = process.argv.slice(2);
if (!catalogFile || !repositoriesDir || !outputFile) {
  throw new Error('Usage: generate-xdb-source-reviews.mjs CATALOG REPOSITORIES_DIR OUTPUT');
}

const catalog = JSON.parse(fs.readFileSync(catalogFile, 'utf8'));
const reviewedAt = new Date().toISOString();
const textExtensions = new Set(['.md', '.txt', '.py', '.rb', '.js', '.mjs', '.ts', '.go', '.sh', '.yml', '.yaml', '.json', '.html']);
const routePattern = /["'`](\/(?:api\/v\d+|api\/graphql|users|uploads|projects|groups|oauth|admin|[^\s"'`]{1,80}\/-(?:\/[^\s"'`]{0,100})?)[^\s"'`]{0,160})["'`]/gi;
const methodPattern = /\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b/g;
const authPattern = /\b(private[-_ ]?token|authorization|bearer|access[-_ ]?token|csrf|session|cookie|login|password)\b/gi;

function filesUnder(root) {
  const result = [];
  const pending = [root];
  while (pending.length) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'vendor') continue;
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) pending.push(full);
      else if (entry.isFile() && textExtensions.has(path.extname(entry.name).toLowerCase()) && entry.size <= 1_000_000) result.push(full);
    }
  }
  return result;
}

const reviews = {};
for (const vulnerability of catalog.vulnerabilities) {
  for (const match of vulnerability.vulnCheckXdb?.matches || []) {
    if (['automated-route-grep', 'repository-availability-check'].includes(match.sourceReview?.depth)) {
      reviews[match.id] = { cve: vulnerability.id, repo: match.repo, ...match.sourceReview };
      continue;
    }
    if (match.sourceReview?.reviewedAt) continue;
    const root = path.join(repositoriesDir, match.id);
    if (!fs.existsSync(root)) {
      const cloneError = `${root}.error`;
      if (!fs.existsSync(cloneError) || !fs.readFileSync(cloneError, 'utf8').trim()) continue;
      reviews[match.id] = {
        cve: vulnerability.id,
        repo: match.repo,
        depth: 'repository-availability-check',
        reviewedAt,
        routeCandidates: [],
        methods: [],
        authenticationSignals: [],
        evidenceFiles: [],
        triggerUsesApi: false,
        availability: 'unavailable',
        finding: 'The repository advertised by XDB returned HTTP 404 and could not be cloned at review time. No source-level exploit claim can be made from this match.'
      };
      continue;
    }
    const routes = new Set();
    const methods = new Set();
    const authIndicators = new Set();
    const evidenceFiles = new Set();
    for (const file of filesUnder(root)) {
      const text = fs.readFileSync(file, 'utf8');
      const relative = path.relative(root, file);
      let relevant = false;
      for (const found of text.matchAll(routePattern)) {
        routes.add(found[1].replace(/\\[/?&=]/g, (value) => value.slice(1)));
        relevant = true;
      }
      for (const found of text.matchAll(methodPattern)) methods.add(found[1]);
      for (const found of text.matchAll(authPattern)) authIndicators.add(found[1].toLowerCase());
      if (relevant) evidenceFiles.add(relative);
    }
    const routeCandidates = [...routes].slice(0, 20);
    const authenticationSignals = [...authIndicators].slice(0, 20);
    reviews[match.id] = {
      cve: vulnerability.id,
      repo: match.repo,
      depth: 'automated-route-grep',
      reviewedAt,
      routeCandidates,
      methods: [...methods].sort(),
      authenticationSignals,
      evidenceFiles: [...evidenceFiles].slice(0, 20),
      triggerUsesApi: routeCandidates.some((route) => /^\/api\//.test(route)),
      finding: routeCandidates.length
        ? `Source contains ${routeCandidates.length} GitLab HTTP route candidate(s). Authentication words and setup code are indicators only; this automated review does not establish a working exploit.`
        : 'No GitLab HTTP route candidate was found by the bounded source scan; this may be a local harness, documentation-only repository, or an implementation the heuristic did not recognize.',
    };
  }
}

const temporary = `${outputFile}.tmp`;
fs.writeFileSync(temporary, `${JSON.stringify({ schemaVersion: 1, generatedAt: reviewedAt, reviews }, null, 2)}\n`);
fs.renameSync(temporary, outputFile);
console.error(`Wrote ${Object.keys(reviews).length} source reviews to ${outputFile}`);
