#!/usr/bin/env node

import fs from 'node:fs';

const [baseUrl, output] = process.argv.slice(2);
if (!baseUrl || !output) throw new Error('Usage: fetch-nvd.mjs URL OUTPUT');

const pageSize = 2000;
let startIndex = 0;
let totalResults = Infinity;
let vulnerabilities = [];

while (startIndex < totalResults) {
  const url = new URL(baseUrl);
  url.searchParams.set('resultsPerPage', String(pageSize));
  url.searchParams.set('startIndex', String(startIndex));
  const response = await fetch(url, { headers: { 'User-Agent': 'gitlab-offline-prioritizer/1.0' } });
  if (!response.ok) throw new Error(`NVD request failed: HTTP ${response.status} for ${url}`);
  const page = await response.json();
  if (!Array.isArray(page.vulnerabilities) || !Number.isInteger(page.totalResults)) {
    throw new Error(`Unexpected NVD response for ${url}`);
  }
  totalResults = page.totalResults;
  vulnerabilities.push(...page.vulnerabilities);
  startIndex += page.vulnerabilities.length;
  const checkpoint = `${output}.tmp`;
  fs.writeFileSync(checkpoint, `${JSON.stringify({
    ...page,
    resultsPerPage: vulnerabilities.length,
    startIndex: 0,
    totalResults,
    vulnerabilities,
  })}\n`);
  fs.renameSync(checkpoint, output);
  console.error(`NVD ${vulnerabilities.length}/${totalResults}`);
  if (!page.vulnerabilities.length && startIndex < totalResults) {
    throw new Error('NVD returned an empty page before totalResults was reached');
  }
}

if (vulnerabilities.length !== totalResults) {
  throw new Error(`NVD completeness failure: received ${vulnerabilities.length}/${totalResults}`);
}
