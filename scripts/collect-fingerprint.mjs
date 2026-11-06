#!/usr/bin/env node

// Collect a schema-v2 build signature from an isolated GitLab release instance.
// Output is a single `builds[]` entry ready to merge into poc/fingerprints.json.
//
// The signature is built from cross-origin-observable signals only:
//   - assetsPresent: content-hashed chunk paths from the "default" entrypoint
//     (loaded on every page) plus a few distinctive page chunks. Probed in the
//     browser with <link rel=preload>/<img> load vs 404, which needs no CORS.
//   - graphqlQueryFieldsSha256: SHA-256 of the sorted anonymous Query-type field
//     names. Readable cross-origin because /api/graphql sends ACAO: *.
// manifestPathsSha256 is recorded for same-origin/token corroboration only;
// /assets/webpack/manifest.json is NOT readable cross-origin.
//
// Patch releases whose changes were backend-only emit a byte-identical asset set.
// Collect several adjacent patches: when their assetsPresent match, group them
// under one build entry and widen versionRange rather than creating duplicates.

import crypto from 'node:crypto';

const args = process.argv.slice(2);
const rawBaseUrl = args.find((value) => !value.startsWith('--'));
const declaredVersion = args.find((value) => value.startsWith('--version='))?.slice(10) || null;
const declaredEdition = args.find((value) => value.startsWith('--edition='))?.slice(10) || null;
const token = process.env.GITLAB_READ_ONLY_TOKEN || '';
if (!rawBaseUrl) throw new Error('Usage: collect-fingerprint.mjs GITLAB_BASE_URL [--version=X.Y.Z --edition=community|enterprise]');
const baseUrl = rawBaseUrl.replace(/\/$/, '');

async function getJson(path, headers = {}) {
  const response = await fetch(`${baseUrl}${path}`, { headers });
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.json();
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

const manifest = await getJson('/assets/webpack/manifest.json');
const publicPath = typeof manifest.publicPath === 'string' ? manifest.publicPath : '/assets/webpack/';
const toPath = (name) => new URL(name, new URL(publicPath, `${baseUrl}/`)).pathname;

// Full normalized asset path set -> same-origin corroboration hash.
const manifestPaths = [...new Set((manifest.assets || []).map((asset) => asset?.name)
  .filter((value) => typeof value === 'string')
  .filter((value) => /\.(?:js|css|png|svg|woff2?)(?:\?|$)/i.test(value))
  .map(toPath))].sort();
const manifestPathsSha256 = sha256(`${manifestPaths.join('\n')}\n`);

// Pick probes: the "default" entrypoint (always loaded) plus distinctive pages.
const entrypoints = manifest.entrypoints || {};
const jsFiles = (name) => (entrypoints[name]?.assets || [])
  .map((asset) => (typeof asset === 'string' ? asset : asset?.name))
  .filter((value) => typeof value === 'string' && value.endsWith('.js'));
const assetsPresent = [];
for (const file of jsFiles('default')) assetsPresent.push(toPath(file));
for (const page of ['super_sidebar', 'pages.sessions.new', 'pages.root', 'sandboxed_mermaid', 'pages.projects.blob.show']) {
  const files = jsFiles(page);
  if (files.length) assetsPresent.push(toPath(files[files.length - 1]));
}
if (assetsPresent.length < 3) {
  throw new Error('Fewer than 3 content-hashed probes found; this manifest layout is unexpected for a 10.0+ build');
}

// Anonymous GraphQL Query-schema signature (cross-origin readable channel).
let graphqlQueryFieldsSha256 = null;
let graphqlQueryFieldCount = null;
try {
  const response = await fetch(`${baseUrl}/api/graphql`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: '{ __type(name: "Query") { fields { name } } }' })
  });
  const json = await response.json();
  const fields = (json?.data?.__type?.fields || []).map(({ name }) => name).sort();
  if (fields.length) {
    graphqlQueryFieldsSha256 = sha256(`${fields.join('\n')}\n`);
    graphqlQueryFieldCount = fields.length;
  }
} catch { /* schema introspection may be disabled; signature stays asset-only */ }

let authoritative = null;
if (token) authoritative = await getJson('/api/v4/version', { 'Private-Token': token });

const version = authoritative?.version?.match(/^\d+\.\d+\.\d+/)?.[0] || declaredVersion;
const edition = authoritative?.enterprise === true ? 'enterprise' :
  authoritative?.enterprise === false ? 'community' : declaredEdition;
if (!version || !edition) {
  throw new Error('A version and edition are required from the authenticated API or explicit --version/--edition metadata');
}

const buildEntry = {
  buildId: `${edition === 'enterprise' ? 'ee' : 'ce'}-${version}`,
  edition,
  frontendWebpackHash: manifest.hash || null,
  versions: [version],
  versionRange: { min: version, max: version },
  confidence: 'exact-build',
  collection: {
    assetNames: `Collected from ${baseUrl} on ${new Date().toISOString()}.`,
    note: 'If an adjacent patch yields an identical assetsPresent set, merge into one entry and widen versionRange instead of adding a duplicate.'
  },
  signals: {
    assetsPresent,
    assetsAbsent: [],
    graphqlQueryFieldsSha256,
    graphqlQueryFieldCount,
    manifestPathsSha256
  }
};

console.log(JSON.stringify({
  _hint: 'Merge the build object below into poc/fingerprints.json -> builds[]. Collect adjacent patch releases before trusting versionRange.',
  authoritativeVersion: authoritative?.version || null,
  authoritativeRevision: authoritative?.revision || null,
  build: buildEntry
}, null, 2));
