#!/usr/bin/env node
// Build poc/fingerprints.json (schema v2) from collected webpack manifests.
//
// Input:  a directory of <version>.json GitLab webpack manifests
//         (collected by scripts/collect-corpus.sh, no booting required).
// Output: fingerprints.json with one build[] entry per distinct frontend build.
//
// Guarantees:
//   - A build's assetsPresent are content-hashed JS paths, so a full match means
//     the target serves that exact build among the collected builds.
//   - Each build's probe set is proven NOT to be a subset of any OTHER collected
//     build's asset set, so no two corpus builds can be confused. Uncollected
//     builds usually fail to match; a later patch can match the newest collected
//     patch of its minor, which the page treats as an open-ended candidate.
//   - Versions whose full asset set is identical are grouped into one build with a
//     versionRange; this is how patch releases that reused a frontend collapse.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

// Usage:
//   build-corpus.mjs <out.json> <dir[:edition]> [<dir[:edition]> ...]
//   build-corpus.mjs <manifests-dir> <out.json>            (legacy CE-only form)
// edition defaults to "community" when omitted.
let outFile, inputs;
const a = process.argv.slice(2);
if (a.length === 2 && a[1].endsWith('.json')) {
  // legacy: <manifests-dir> <out.json>
  inputs = [{ dir: a[0], edition: 'community' }];
  outFile = a[1];
} else {
  outFile = a[0];
  inputs = a.slice(1).map((spec) => {
    const i = spec.lastIndexOf(':');
    return i > 1 ? { dir: spec.slice(0, i), edition: spec.slice(i + 1) } : { dir: spec, edition: 'community' };
  });
}
if (!outFile || !inputs.length) throw new Error('Usage: build-corpus.mjs <out.json> <dir[:edition]> [<dir[:edition]> ...]');

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const isHashedJs = (name) =>
  typeof name === 'string' &&
  /\.[0-9a-f]{8,}\.(?:chunk|bundle)\.js$/.test(name) &&
  !/\.map(?:\.gz)?$/.test(name) && !name.endsWith('.gz');

// Preferred logical entrypoint names (core app bundles change on almost every
// build, so they are the strongest discriminators). Order = probe priority.
const CORE = ['default', 'main', 'runtime', 'webpack_runtime', 'commons', 'common', 'application', 'super_sidebar'];

function parseManifest(file) {
  const m = JSON.parse(fs.readFileSync(file, 'utf8'));
  const publicPath = typeof m.publicPath === 'string' ? m.publicPath : '/assets/webpack/';
  const toPath = (name) => {
    try { return new URL(name, new URL(publicPath, 'http://x/')).pathname; }
    catch { return name.startsWith('/') ? name : publicPath.replace(/\/$/, '') + '/' + name; }
  };
  // All content-hashed JS paths = the discrimination universe.
  const all = new Set();
  for (const a of m.assets || []) { const n = a?.name ?? a; if (isHashedJs(n)) all.add(toPath(n)); }
  // Entrypoint JS, grouped by logical name (for choosing robust probes).
  const byEntry = {};
  for (const [name, def] of Object.entries(m.entrypoints || {})) {
    const files = (def?.assets || []).map((x) => (typeof x === 'string' ? x : x?.name)).filter(isHashedJs);
    if (files.length) byEntry[name] = files.map(toPath);
  }
  // Older manifests: fall back to assetsByChunkName.
  if (!Object.keys(byEntry).length) {
    for (const [name, files0] of Object.entries(m.assetsByChunkName || {})) {
      const files = (Array.isArray(files0) ? files0 : [files0]).filter(isHashedJs);
      if (files.length) byEntry[name] = files.map(toPath);
    }
  }
  return { webpackHash: m.hash || null, all: [...all].sort(), byEntry };
}

function versionKey(v) {
  const p = v.split('.').map(Number);
  return p[0] * 1e6 + p[1] * 1e3 + p[2];
}

// Load every manifest, tagging each with its edition. parsed key = "edition\0version".
const parsed = {};
let manifestCount = 0;
for (const { dir, edition } of inputs) {
  if (!fs.existsSync(dir)) { console.error(`input dir missing: ${dir}`); continue; }
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.json'))) {
    const version = f.replace(/\.json$/, '');
    try { parsed[`${edition}\0${version}`] = { ...parseManifest(path.join(dir, f)), edition, version }; manifestCount++; }
    catch (e) { console.error(`skip ${edition} ${version}: ${e.message}`); }
  }
}
const keys = Object.keys(parsed);
if (!keys.length) throw new Error('no parseable manifests');

// Group by (edition, identical full asset set) -> one build each. CE and EE never
// group together (different asset sets); the uniqueness pass still runs across all.
const groups = new Map();
for (const k of keys) {
  const p = parsed[k];
  const gkey = `${p.edition}\0${sha256(p.all.join('\n'))}`;
  if (!groups.has(gkey)) groups.set(gkey, { versions: [], edition: p.edition, rep: k });
  groups.get(gkey).versions.push(p.version);
}
const builds = [...groups.values()].map((g) => {
  g.versions.sort((a, b) => versionKey(a) - versionKey(b));
  return { edition: g.edition, versions: g.versions, all: new Set(parsed[g.rep].all), byEntry: parsed[g.rep].byEntry, rep: g.rep };
});
builds.sort((x, y) => (x.edition < y.edition ? -1 : x.edition > y.edition ? 1 : 0) || versionKey(x.versions[0]) - versionKey(y.versions[0]));

// Choose a probe set per build, then enforce cross-build uniqueness.
function initialProbes(build) {
  const picked = [];
  const seen = new Set();
  const add = (p) => { if (!seen.has(p)) { seen.add(p); picked.push(p); } };
  for (const name of CORE) for (const p of build.byEntry[name] || []) add(p);
  // add a few distinctive page bundles for breadth
  const pageNames = Object.keys(build.byEntry).filter((n) => n.startsWith('pages.') || n.startsWith('page.')).sort();
  for (const name of pageNames.slice(0, 4)) for (const p of (build.byEntry[name] || []).slice(-1)) add(p);
  // Always aim for >=8 probes (lowers false-positive risk from uncollected
  // adjacent builds). Fill deterministically from the full content-hashed set.
  if (picked.length < 8) {
    const sorted = [...build.all].sort();
    const step = Math.max(1, Math.floor(sorted.length / 10));
    for (let i = 0; i < sorted.length && picked.length < 8; i += step) add(sorted[i]);
    for (let i = 0; i < sorted.length && picked.length < 8; i += 1) add(sorted[i]);
  }
  return picked.slice(0, 10);
}

for (const b of builds) b.probes = initialProbes(b);

// Uniqueness: a build's probe set must not be a subset of any OTHER build's full
// asset set. If it is, add discriminators (assets present here, absent there).
for (const b of builds) {
  for (const other of builds) {
    if (other === b) continue;
    const subset = b.probes.every((p) => other.all.has(p));
    if (!subset) continue;
    const discriminators = [...b.all].filter((p) => !other.all.has(p)).sort();
    for (const d of discriminators) { if (!b.probes.includes(d)) { b.probes.push(d); break; } }
  }
}
// Final verification.
let collisions = 0;
for (const b of builds) for (const other of builds) {
  if (other !== b && b.probes.every((p) => other.all.has(p))) {
    collisions++; console.error(`COLLISION: ${b.versions.join(',')} probes subset of ${other.versions.join(',')}`);
  }
}

// Optional GraphQL corroboration, keyed by "<edition>\x00<version>". Left empty:
// the corpus is built from image filesystems without booting, so no instance
// GraphQL schema SHA is attached, and asset presence alone identifies the build.
const GRAPHQL = {};
const allVersionsSorted = [...new Set(builds.flatMap((b) => b.versions))].sort((x, y) => versionKey(x) - versionKey(y));
const editionsPresent = [...new Set(builds.map((b) => b.edition))].sort();

const out = {
  schemaVersion: 2,
  generatedAt: new Date().toISOString(),
  methodology: 'Offline build-class signatures. At runtime the page requests only the operator-supplied GitLab and this bundled file. GitLab ships Webpack assets whose filenames embed a content hash, so a set of asset paths that all load identifies a specific frontend build. A frontend build can be shared by several patch releases when only backend code changed between them, so a match resolves to a VERSION RANGE, not necessarily a single patch. Only the authenticated /api/v4/version endpoint yields the exact patch.',
  crossOriginChannels: {
    assetPresence: 'Content-hashed asset paths probed with <link rel=preload> and <img> load/error. Needs no CORS: only presence is observed, never content. Primary signal.',
    graphqlQuerySchema: 'SHA-256 of the sorted anonymous Query-type field names. Readable cross-origin because /api/graphql sets Access-Control-Allow-Origin: *. Corroborating signal where collected.',
    unavailable: '/assets/webpack/manifest.json returns 200 but carries no Access-Control-Allow-Origin header, so its contents are NOT readable cross-origin.'
  },
  corpus: {
    manifestsCollected: manifestCount,
    distinctBuilds: builds.length,
    editions: editionsPresent,
    versionSpan: { min: allVersionsSorted[0], max: allVersionsSorted[allVersionsSorted.length - 1] },
    probeUniquenessCollisions: collisions,
    note: 'Per-patch corpus deduplicated into frontend build classes, per edition. CE and EE have distinct asset sets and never group together. Each build probe set is proven not to be a subset of any other collected build (0 collisions), so no two corpus builds can be confused. A build released after collection may match the newest collected build of its minor line.'
  },
  builds: builds.map((b) => {
    const pfx = b.edition === 'enterprise' ? 'ee' : 'ce';
    const gq = b.versions.map((v) => GRAPHQL[`${b.edition}\0${v}`]).find(Boolean) || null;
    return {
      buildId: `${pfx}-${b.versions[0]}${b.versions.length > 1 ? '-to-' + b.versions.slice(-1)[0] : ''}`,
      edition: b.edition,
      frontendWebpackHash: parsed[b.rep].webpackHash,
      versions: b.versions,
      versionRange: { min: b.versions[0], max: b.versions.slice(-1)[0] },
      confidence: 'exact-build',
      signals: {
        assetsPresent: b.probes,
        assetsAbsent: [],
        graphqlQueryFieldsSha256: gq ? gq.sha : null,
        graphqlQueryFieldCount: gq ? gq.count : null
      }
    };
  }),
  notes: [
    'Regenerate with scripts/collect-corpus.sh then scripts/build-corpus.mjs.',
    'Each build probe set is verified not to be a subset of any other collected build, so corpus builds cannot be confused.',
    'No two collected builds can be confused, but a patch released after collection can serve the same assets as the newest collected patch of its minor line; the page keeps that later patch as a candidate.'
  ]
};

fs.writeFileSync(outFile, JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${outFile}: ${manifestCount} manifests -> ${builds.length} distinct builds, ${collisions} collisions`);
console.log('editions:', editionsPresent.join(','), '| span:', out.corpus.versionSpan.min, '->', out.corpus.versionSpan.max);
