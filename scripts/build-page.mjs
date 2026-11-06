#!/usr/bin/env node
/*
 * Build a single, fully self-contained poc/index.html into dist/index.html.
 *
 * Everything the page needs at runtime is inlined:
 *   - the version fingerprint corpus (poc/fingerprints.json)
 *   - the CVE catalogue (poc/cves/gitlab-10.0.0-and-later.json)
 *   - any local <script src>, <link rel=stylesheet>, <img src> or url(...) asset
 *     (fonts, images) is read from disk and inlined as a data: URI
 *
 * The page keeps a dev fallback (fetch from disk) so poc/index.html still works
 * when served directly; the build simply makes those fetches unnecessary by
 * defining window.__FINGERPRINTS__ / window.__CVES__ before the main script runs.
 *
 * A verification pass then asserts the output has NO runtime external dependency
 * other than the probes the page fires at the user-supplied GitLab target. If any
 * asset would still be loaded, the build fails loudly.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const srcDir = path.join(root, 'poc');
const srcHtml = path.join(srcDir, 'index.html');
const outDir = path.join(root, 'dist');
const outHtml = path.join(outDir, 'index.html');

const read = (p) => fs.readFileSync(p, 'utf8');
const readJson = (p) => JSON.parse(read(p));

// JSON embedded in a <script> must not let any "</script>" (or comment opener)
// terminate the element early. Escape the three characters that can.
const safeJson = (value) =>
  JSON.stringify(value).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/\u2028|\u2029/g, (c) =>
    c === '\u2028' ? '\\u2028' : '\\u2029');

const MIME = {
  '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf', '.otf': 'font/otf',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
  '.svg': 'image/svg+xml', '.webp': 'image/webp', '.ico': 'image/x-icon',
  '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json',
};
const dataUri = (file) => {
  const ext = path.extname(file).toLowerCase();
  const mime = MIME[ext] || 'application/octet-stream';
  const b64 = fs.readFileSync(file).toString('base64');
  return `data:${mime};base64,${b64}`;
};

function main() {
  let html = read(srcHtml);
  const fingerprints = readJson(path.join(srcDir, 'fingerprints.json'));
  const cves = readJson(path.join(srcDir, 'cves', 'gitlab-10.0.0-and-later.json'));

  // 1) Inline local <script src="...">  (skip absolute http(s) and data: URIs).
  html = html.replace(/<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*><\/script>/gi, (m, src) => {
    if (/^(https?:)?\/\//i.test(src) || src.startsWith('data:')) {
      throw new Error(`Refusing to build: external <script src="${src}"> cannot be inlined`);
    }
    return `<script>\n${read(path.join(srcDir, src))}\n</script>`;
  });

  // 2) Inline local stylesheets <link rel="stylesheet" href="...">.
  html = html.replace(/<link\b[^>]*rel=["']stylesheet["'][^>]*>/gi, (m) => {
    const href = (m.match(/href=["']([^"']+)["']/i) || [])[1];
    if (!href) return m;
    if (/^(https?:)?\/\//i.test(href)) {
      throw new Error(`Refusing to build: external stylesheet "${href}" cannot be inlined`);
    }
    return `<style>\n${read(path.join(srcDir, href))}\n</style>`;
  });

  // 3) Inline local <img src="..."> and url(...) references as data: URIs.
  const inlineAsset = (ref) => {
    if (/^(https?:)?\/\//i.test(ref) || ref.startsWith('data:') || ref.startsWith('#')) return null;
    const file = path.join(srcDir, ref.split(/[?#]/)[0]);
    if (!fs.existsSync(file)) return null;
    return dataUri(file);
  };
  html = html.replace(/(<img\b[^>]*\bsrc=)["']([^"']+)["']/gi, (m, pre, ref) => {
    const uri = inlineAsset(ref);
    return uri ? `${pre}"${uri}"` : m;
  });
  html = html.replace(/url\(\s*(['"]?)([^)'"]+)\1\s*\)/gi, (m, q, ref) => {
    const uri = inlineAsset(ref);
    return uri ? `url("${uri}")` : m;
  });

  // 4) Verify no runtime external/asset dependency survives. Run this BEFORE the
  //    data is inlined, so the embedded CVE/corpus JSON (which may itself contain
  //    strings like "url(...)" in descriptions) can never cause a false positive.
  const problems = [];
  if (/<script\b[^>]*\bsrc=/i.test(html)) problems.push('a <script src=...> remains');
  if (/<link\b[^>]*rel=["']stylesheet["']/i.test(html)) problems.push('a <link rel=stylesheet> remains');
  for (const m of html.matchAll(/<img\b[^>]*\bsrc=["']([^"']+)["']/gi)) {
    if (!m[1].startsWith('data:')) problems.push(`a non-inlined <img src="${m[1]}"> remains`);
  }
  // Scan only CSS (inside <style> blocks) for url(...), so JS like `new URL(x)`
  // never trips it. Flag any local relative target (not a data: URI, remote URL,
  // CSS var, or fragment) that was not inlined.
  for (const style of html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)) {
    for (const m of style[1].matchAll(/url\(\s*(['"]?)([^)]+?)\1\s*\)/gi)) {
      const ref = m[2].trim();
      if (ref.startsWith('data:') || ref.startsWith('#') || ref.startsWith('var(') || /^(https?:)?\/\//i.test(ref)) continue;
      problems.push(`a non-inlined url(${ref}) remains`);
    }
  }
  if (problems.length) throw new Error('Self-containment check failed:\n  - ' + problems.join('\n  - '));

  // 5) Inject the data globals immediately before the main script so loadData()
  //    finds them and never fetches from disk.
  const marker = '<script>\n    /* Data seam:';
  if (!html.includes(marker)) throw new Error('Could not find the main script marker to inject data before');
  const dataScript =
    `<script>\n` +
    `  window.__FINGERPRINTS__ = ${safeJson(fingerprints)};\n` +
    `  window.__CVES__ = ${safeJson(cves)};\n` +
    `</script>\n  `;
  // A replacer FUNCTION, not a string: a string replacement expands $', $`, $& and $$,
  // and the inlined data (NVD CVE descriptions) is third-party text that can contain
  // them, which would splice raw page source (including </script>) into the data block.
  html = html.replace(marker, () => dataScript + marker);
  const injectedAt = html.indexOf(dataScript);
  if (injectedAt === -1 || html.indexOf(marker, injectedAt) !== injectedAt + dataScript.length) {
    throw new Error('data block was not injected verbatim');
  }
  if (!/window\.__FINGERPRINTS__\s*=/.test(html)) throw new Error('fingerprint data was not injected');
  if (!/window\.__CVES__\s*=/.test(html)) throw new Error('CVE data was not injected');

  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(outHtml, html);

  // Copy out-of-band assets that crawlers and iOS fetch by URL (the social share
  // card and the apple-touch icon), so they ship next to the page. These are never
  // requested during a normal page view, so the page stays self-contained at runtime.
  for (const asset of ['og-image.png', 'apple-touch-icon.png']) {
    const from = path.join(srcDir, asset);
    if (fs.existsSync(from)) { fs.copyFileSync(from, path.join(outDir, asset)); console.log(`  copied ${asset}`); }
  }
  const kb = (Buffer.byteLength(html) / 1024).toFixed(0);
  console.log(`Built ${path.relative(root, outHtml)} (${kb} KB, single self-contained file)`);
  console.log(`  corpus builds: ${fingerprints.builds.length}`);
  console.log(`  CVE records:   ${cves.vulnerabilities.length}`);
}

main();
