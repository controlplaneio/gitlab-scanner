#!/usr/bin/env node

import fs from 'node:fs';

const args = process.argv.slice(2);
const input = args.find((arg) => !arg.startsWith('--')) || 'poc/cves/gitlab-10.0.0-and-later.json';
const refreshXdb = args.includes('--refresh-xdb');
const refreshXdbUncertain = args.includes('--refresh-xdb-uncertain');
const xdbSeedFiles = args
  .filter((arg) => arg.startsWith('--seed-xdb='))
  .map((arg) => arg.slice('--seed-xdb='.length));
const xdbSourceReviewFiles = args
  .filter((arg) => arg.startsWith('--source-reviews='))
  .map((arg) => arg.slice('--source-reviews='.length));
const catalog = JSON.parse(fs.readFileSync(input, 'utf8'));
const reviewedAt = new Date().toISOString();

function checkpointCatalog() {
  const temporary = `${input}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(catalog, null, 2)}\n`);
  fs.renameSync(temporary, input);
}

for (const seedFile of xdbSeedFiles) {
  const seed = JSON.parse(fs.readFileSync(seedFile, 'utf8'));
  const byId = new Map(seed.vulnerabilities.map((item) => [item.id, item.vulnCheckXdb]));
  for (const item of catalog.vulnerabilities) {
    if (!item.vulnCheckXdb && byId.get(item.id)) item.vulnCheckXdb = byId.get(item.id);
  }
}

const xdbApiUrl = (cve) => `https://www.vulncheck.com/api/xdb/?cve=${encodeURIComponent(cve)}`;

// Deliberately shallow source checks: stop once the delivery route is clear.
// These are keyed by VulnCheck XDB's stable result id so a refresh can retain
// the finding without treating every repository as a working GitLab exploit.
const xdbSourceReviews = {
  cff2308ddcbf: {
    depth: 'superficial-route-grep', triggerRoute: '/:namespace/:project/-/blob/:ref/:path?format=json&viewer=rich',
    triggerUsesApi: false, apiUse: 'authenticated project setup and cleanup only',
    finding: 'The CVE-2026-110264 driver triggers an anonymous blob-viewer GET; its /api/v4 calls prepare or remove the project.',
  },
  '1f7a47488276': {
    depth: 'superficial-route-grep', triggerRoute: '/:namespace/:project/-/blob/:ref/:path?format=json&viewer=rich',
    triggerUsesApi: false, apiUse: 'version probing and authenticated lab provisioning only',
    finding: 'The exploit function uses the non-API rich blob viewer; /api/v4/version and project/file API calls are checks or setup.',
  },
  abec50a6080a: {
    depth: 'superficial-route-grep', triggerRoute: null, triggerUsesApi: false, apiUse: 'none',
    finding: 'Standalone Onigmo engine harness; it explicitly does not demonstrate a reachable GitLab route.',
  },
  fdd28647d723: {
    depth: 'superficial-route-grep', triggerRoute: '/re (standalone lab)', triggerUsesApi: false, apiUse: 'none',
    finding: 'Standalone regex lab endpoint, not a GitLab HTTP/API delivery reproduction.',
  },
  '844c42b8c0a8': {
    depth: 'superficial-route-grep', triggerRoute: '/api/v4/projects/:id/repository/files/README.org/raw?ref=main',
    triggerUsesApi: true, apiUse: 'candidate API surface, not a completed exploit',
    finding: 'The source requests an anonymous /api/v4 raw-file route, but labels payload placement and the native crasher as pending; this is not proof that the API request reaches the vulnerable renderer.',
  },
  '4d234da69ec6': {
    depth: 'superficial-route-grep', triggerRoute: '/:namespace/:project/-/blob/:ref/:path?format=json&viewer=rich',
    triggerUsesApi: false, apiUse: 'authenticated project/file setup only',
    finding: 'The PoC trigger is an anonymous rich blob-viewer GET; setup.py uses /api/v4 with a token to plant the file.',
  },
  '76c496ae3b42': {
    depth: 'superficial-route-grep', triggerRoute: null, triggerUsesApi: false, apiUse: 'none',
    finding: 'Local Ruby/Onigmo crash harness; no HTTP request implementation was found.',
  },
  '9e12e3889cb1': {
    depth: 'superficial-route-grep',
    triggerRoute: '/api/v4/projects/:id/pipeline_schedules/:schedule_id/play or /api/graphql',
    triggerUsesApi: true,
    apiUse: 'exploit trigger, but every path supplies an attacker PRIVATE-TOKEN or GraphQL token',
    finding: 'The source directly triggers REST or GraphQL pipeline-schedule APIs, but explicitly requires a Developer-capable attacker token; it does not raise likelihood in the anonymous hostile-page threat model.',
  },
  '47e63f747633': {
    depth: 'superficial-route-grep', triggerRoute: '/users/auth/saml/callback',
    triggerUsesApi: false, apiUse: 'none',
    finding: 'The lab and Nuclei flow forge and submit a SAMLResponse to the non-API callback. It requires configured SAML and a legitimately signed IdP response.',
  },
  bbbf2dd62a91: {
    depth: 'superficial-route-grep', triggerRoute: '/users/auth/saml/callback',
    triggerUsesApi: false, apiUse: 'none',
    finding: 'The source transforms an intercepted signed SAML response for form submission to the SAML callback; no GitLab /api trigger is implemented.',
  },
  '85b8ce671d18': {
    depth: 'superficial-route-grep', triggerRoute: '/api/v4/projects/:id/ci/lint?content_ref=:branch',
    triggerUsesApi: true, apiUse: 'anonymous exploit trigger after authenticated repository setup',
    finding: 'The source triggers CI lint through an anonymous API GET, but first uses an attacker token and Git push to seed a crafted public project and branch.',
  },
  '82e28bb3c98f': {
    depth: 'superficial-route-grep', triggerRoute: '/api/v4/projects/:id/repository/commits/ or /repository/files/:name/',
    triggerUsesApi: true, apiUse: 'unauthenticated exploit trigger',
    finding: 'The source sends form or JSON POST requests to trailing-slash GitLab repository API routes without a required token and reads the file-disclosure response.',
  },
  '637796c5f0a2': {
    depth: 'superficial-route-grep', triggerRoute: '/api/graphql', triggerUsesApi: true,
    apiUse: 'unauthenticated exploit trigger',
    finding: 'The source sends an unauthenticated GraphQL request using @gl_introduced and a fallback method name to delete a public project.',
  },
  '1960199b1dec': {
    depth: 'superficial-route-grep', triggerRoute: '/:namespace/:project/-/tags?format=atom',
    triggerUsesApi: false, apiUse: '/api/v4/projects is discovery only',
    finding: 'The source uses /api/v4 only to find projects; the email leak is read from a non-API Atom tag feed.',
  },
  '44c05ef0c116': {
    depth: 'superficial-route-grep', triggerRoute: '/users/password', triggerUsesApi: false, apiUse: 'none',
    finding: 'The source reads a CSRF token from /users/password/new and submits the non-API password-reset form; no GitLab API trigger is used.',
  },
  '5d508f25cf42': {
    depth: 'superficial-route-grep', triggerRoute: '/:namespace/.../:project/uploads/:secret/..%2f...',
    triggerUsesApi: false, apiUse: 'none',
    finding: 'The source creates nested groups, a project, and an upload through authenticated HTML forms, then reads the traversal result from a non-API upload route.',
  },
  '8d1c1b12cbe8': {
    depth: 'superficial-route-grep', triggerRoute: '/users/sign_in', triggerUsesApi: false, apiUse: 'none',
    finding: 'The source scrapes usernames and a CSRF token from non-API HTML before attempting login with a vulnerable generated password.',
  },
  '4722f45a5488': {
    depth: 'superficial-route-grep', triggerRoute: '/api/graphql', triggerUsesApi: true,
    apiUse: 'unauthenticated information-disclosure trigger',
    finding: 'The source directly submits an anonymous GraphQL users query and reads usernames, email addresses, memberships, and related profile data.',
  },
  '29556d9ca592': {
    depth: 'superficial-route-grep', triggerRoute: '/api/v4/ci/lint', triggerUsesApi: true,
    apiUse: 'unauthenticated SSRF trigger',
    finding: 'The source posts anonymous JSON to the CI lint API with a remote include URL and checks the resulting external interaction.',
  },
  '26d18020bcb3': {
    depth: 'superficial-route-grep', triggerRoute: '/uploads/user', triggerUsesApi: false, apiUse: 'none',
    finding: 'The source reads a CSRF token and session from /users/sign_in, then submits a multipart file to the non-API upload route.',
  },
  '73e0435eb94a': {
    depth: 'superficial-route-grep', triggerRoute: '/api/graphql', triggerUsesApi: true,
    apiUse: 'unauthenticated information-disclosure trigger',
    finding: 'The source directly posts an anonymous users query to /api/graphql and parses returned usernames and email addresses.',
  },
  '084975498f7a': {
    depth: 'superficial-route-grep', triggerRoute: '/projects', triggerUsesApi: false, apiUse: 'none',
    finding: 'The exploit logs in with supplied credentials, reads CSRF tokens, and submits a crafted project import through non-API HTML routes.',
  },
  d33d8bc56fee: {
    depth: 'superficial-route-grep', triggerRoute: '/api/v4/projects/1/wikis/attachments', triggerUsesApi: true,
    apiUse: 'exploit trigger requiring a private token',
    finding: 'The source triggers the wiki attachment API, but explicitly requires and sends a GitLab private token.',
  },
};

for (const reviewFile of xdbSourceReviewFiles) {
  const external = JSON.parse(fs.readFileSync(reviewFile, 'utf8'));
  Object.assign(xdbSourceReviews, external.reviews || external);
}

function reviewedXdbSource(id, existing = null) {
  const finding = xdbSourceReviews[id];
  return finding ? { ...finding, reviewedAt } : existing;
}

async function mapWithConcurrency(values, limit, worker) {
  const results = new Array(values.length);
  let next = 0;
  async function consume() {
    while (next < values.length) {
      const index = next++;
      results[index] = await worker(values[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, consume));
  return results;
}

async function refreshVulnCheckXdb(items) {
  let completed = 0;
  await mapWithConcurrency(items, 8, async (item) => {
    const queryUrl = xdbApiUrl(item.id);
    const response = await fetch(queryUrl, {
      headers: { Accept: 'application/json', 'User-Agent': 'gitlab-browser-api-assessment/1.0' },
    });
    if (!response.ok) throw new Error(`XDB lookup failed for ${item.id}: HTTP ${response.status}`);
    const body = await response.json();
    if (!body?.meta?.success || !Array.isArray(body.data)) {
      throw new Error(`XDB returned an unexpected response for ${item.id}`);
    }
    item.vulnCheckXdb = {
      queryUrl,
      checkedAt: reviewedAt,
      matches: body.data.map(({ id, xdbId, cve, date, url, type, author, repo }) => ({
        id, xdbId, cve, date, url, type, author, repo,
        sourceReview: reviewedXdbSource(id,
          item.vulnCheckXdb?.matches?.find((entry) => entry.id === id)?.sourceReview || null),
      })),
      interpretation: body.data.length
        ? 'XDB repository matches found; each sourceReview states whether its implementation was inspected.'
        : 'No XDB repository match was returned at lookup time; absence is not proof that no public exploit exists.',
    };
    completed += 1;
    if (completed % 25 === 0 || completed === items.length) {
      checkpointCatalog();
      console.error(`XDB ${completed}/${items.length}`);
    }
  });
}

const assessment = (status, confidence, values = {}) => ({
  status,
  confidence,
  reviewDepth: values.reviewDepth || 'official-advisory',
  route: values.route || null,
  method: values.method || null,
  authentication: values.authentication || 'unknown',
  userInteraction: values.userInteraction ?? false,
  browserMechanism: values.browserMechanism || 'unknown',
  responseReadable: values.responseReadable ?? 'unknown',
  impact: values.impact || 'unknown',
  prerequisites: values.prerequisites || [],
  publicPoc: values.publicPoc || 'not found in reviewed primary references',
  rationale: values.rationale,
  evidenceNotes: values.evidenceNotes || [],
  reviewedAt,
});

const likelihoodByStatus = {
  'confirmed-compatible': 'high',
  'likely-compatible': 'medium-high',
  'conditional-compatible': 'conditional',
  unresolved: 'unknown',
  'outside-threat-model': 'low-in-this-threat-model',
};

const overrides = {
  'CVE-2026-4523': assessment('likely-compatible', 'medium', {
    route: '/api/graphql', method: 'POST', authentication: 'none', browserMechanism: 'CORS fetch',
    responseReadable: true, impact: 'information disclosure', reviewDepth: 'official-advisory-private-details',
    prerequisites: ['Exact GraphQL object identifiers or query prerequisites are not yet public'],
    rationale: 'GitLab describes unauthenticated CI job-trace disclosure through GraphQL. The route is CORS-readable, but the primary work item is still private.',
  }),
  'CVE-2026-7250': assessment('likely-compatible', 'medium', {
    route: '/api/* request parsing middleware', method: 'unknown', authentication: 'none', browserMechanism: 'CORS fetch',
    responseReadable: false, impact: 'denial of service', reviewDepth: 'official-advisory-private-details',
    rationale: 'The official record identifies unauthenticated API request parsing. Exact request shape and browser payload limits are not yet public.',
  }),
  'CVE-2025-12664': assessment('likely-compatible', 'medium', {
    route: '/api/graphql', method: 'POST', authentication: 'none', browserMechanism: 'CORS fetch',
    responseReadable: false, impact: 'denial of service', reviewDepth: 'official-advisory-private-details',
    rationale: 'Repeated unauthenticated GraphQL requests are browser-sendable, but the disclosed primary reproduction is not public.',
  }),
  'CVE-2025-14513': assessment('likely-compatible', 'medium', {
    route: 'protected branches API', method: 'JSON request', authentication: 'none', browserMechanism: 'CORS fetch',
    responseReadable: false, impact: 'denial of service', reviewDepth: 'official-advisory-private-details',
    rationale: 'The advisory explicitly identifies unauthenticated crafted JSON at a GitLab API. The exact route and payload remain private.',
  }),
  'CVE-2026-1662': assessment('unresolved', 'low', {
    route: 'Jira events endpoint', authentication: 'none', impact: 'denial of service', reviewDepth: 'official-advisory-private-details',
    prerequisites: ['Exact endpoint, content type, and integration requirements are not public'],
    rationale: 'The endpoint may be browser-sendable, but its route and any integration secret or preflight requirements are unavailable.',
  }),
  'CVE-2026-1388': assessment('unresolved', 'low', {
    route: 'merge request endpoint', authentication: 'none', impact: 'denial of service', reviewDepth: 'official-advisory-private-details',
    rationale: 'The record says unauthenticated endpoint input, but no route or request form is public enough to establish browser compatibility.',
  }),
  'CVE-2025-14511': assessment('unresolved', 'low', {
    route: 'container registry event endpoint', authentication: 'none', impact: 'denial of service', reviewDepth: 'official-advisory-private-details',
    prerequisites: ['Registry notification endpoints may have non-browser request or secret requirements'],
    rationale: 'The route and expected event authentication are not public, so ordinary hostile-page reachability is not established.',
  }),
  'CVE-2025-8099': assessment('likely-compatible', 'medium', {
    route: '/api/graphql', method: 'POST', authentication: 'none', browserMechanism: 'CORS fetch', impact: 'denial of service',
    reviewDepth: 'official-advisory-private-details', rationale: 'The advisory identifies repeated unauthenticated GraphQL queries; exact query details remain private.',
  }),
  'CVE-2025-12562': assessment('likely-compatible', 'medium', {
    route: '/api/graphql', method: 'POST', authentication: 'none', browserMechanism: 'CORS fetch', impact: 'denial of service',
    reviewDepth: 'official-advisory-private-details', rationale: 'Crafted unauthenticated GraphQL queries are compatible with the observed CORS policy, but the primary reproduction is private.',
  }),
  'CVE-2025-11447': assessment('confirmed-compatible', 'high', {
    route: '/api/graphql', method: 'POST application/json', authentication: 'none', browserMechanism: 'CORS fetch',
    responseReadable: true, impact: 'denial of service', reviewDepth: 'public-primary-reproduction',
    publicPoc: 'GitLab work item includes request structure and reproduction steps',
    prerequisites: ['Large crafted JSON string', 'Several concurrent requests for demonstrated impact'],
    rationale: 'The public GitLab report explicitly confirms an unauthenticated JSON POST to /api/graphql. GitLab default configuration permits this cross-origin preflight and request.',
  }),
  'CVE-2025-10004': assessment('conditional-compatible', 'high', {
    route: '/api/graphql', method: 'POST application/json', authentication: 'none for trigger', browserMechanism: 'CORS fetch',
    responseReadable: true, impact: 'denial of service', reviewDepth: 'public-primary-reproduction',
    publicPoc: 'GitLab work item includes the GraphQL query and reproduction',
    prerequisites: ['Known public project and blob paths', 'Large repository blobs must already exist', 'Repeated or parallel requests'],
    rationale: 'The trigger is an unauthenticated GraphQL read and is browser-compatible, but it depends on suitably large public repository content.',
  }),
  'CVE-2025-8014': assessment('conditional-compatible', 'high', {
    route: '/api/graphql', method: 'POST application/json', authentication: 'none for trigger', browserMechanism: 'CORS fetch',
    responseReadable: true, impact: 'denial of service', reviewDepth: 'public-primary-reproduction',
    publicPoc: 'GitLab work item contains a Python GraphQL flood reproduction',
    prerequisites: ['Public project with many large public snippets', 'Attacker or another user must seed the content', 'Parallel requests'],
    rationale: 'The unauthenticated trigger is browser-compatible, but preparation requires content and ordinarily an authenticated project creator.',
  }),
  'CVE-2025-4225': assessment('conditional-compatible', 'high', {
    route: '/api/graphql', method: 'POST application/json', authentication: 'none for trigger', browserMechanism: 'CORS fetch',
    responseReadable: true, impact: 'denial of service', reviewDepth: 'public-primary-reproduction',
    publicPoc: 'GitLab work item provides the multiplexed snippets query and flood procedure',
    prerequisites: ['Known public project with large snippets', 'Parallel requests'],
    rationale: 'The disclosed unauthenticated GraphQL trigger is browser-compatible but relies on prepared or existing public snippet content.',
  }),
  'CVE-2025-2246': assessment('confirmed-compatible', 'high', {
    route: '/api/graphql', method: 'POST application/json', authentication: 'none', browserMechanism: 'CORS fetch',
    responseReadable: true, impact: 'information disclosure', reviewDepth: 'public-primary-reproduction',
    publicPoc: 'GitLab work item provides the exact GraphQL query',
    prerequisites: ['Target public project containing manual CI/CD variables', 'Project path must be known or discovered'],
    rationale: 'The public report demonstrates unauthenticated secret disclosure from a public project through a CORS-readable GraphQL response.',
  }),
  'CVE-2024-8116': assessment('confirmed-compatible', 'high', {
    route: '/api/graphql', method: 'POST application/json', authentication: 'none', browserMechanism: 'CORS fetch',
    responseReadable: true, impact: 'information disclosure', reviewDepth: 'public-primary-reproduction',
    publicPoc: 'GitLab work item provides the exact protectableBranches query',
    prerequisites: ['Public project with repository visibility restricted', 'Project path must be known'],
    rationale: 'The disclosed query returns protected branch names without authentication and the response is readable through GitLab API CORS.',
  }),
  'CVE-2026-110264': assessment('conditional-compatible', 'high', {
    route: '/:namespace/:project/-/blob/:ref/:path?format=json&viewer=rich', method: 'GET',
    authentication: 'none for trigger', browserMechanism: 'simple cross-origin GET (response need not be readable)',
    responseReadable: false, impact: 'remote code execution', reviewDepth: 'public-exploit-source-superficial-review',
    publicPoc: 'Three XDB repositories implement the same anonymous rich blob-viewer trigger',
    prerequisites: ['A crafted .org file must already exist in a public project', 'Planting that file normally requires authenticated project write access', 'Public repositories demonstrate the vulnerable rendering path, but not every repository demonstrates weaponized command execution'],
    rationale: 'Multiple public exploit sources trigger the vulnerable Org renderer with an anonymous simple GET. It is not an /api route, but a hostile page can still send the request without reading the response. The content-seeding prerequisite makes the result conditional.',
    evidenceNotes: ['A fourth XDB source calls an /api/v4 raw-file endpoint, but describes the crasher and payload placement as pending, so that API call is not counted as a confirmed trigger.'],
  }),
  'CVE-2026-82837': assessment('outside-threat-model', 'high', {
    authentication: 'required', impact: 'information disclosure', rationale: 'The advisory explicitly requires an authenticated user; the hostile public page has no GitLab token or ambient cross-site session.',
  }),
  'CVE-2026-6336': assessment('unresolved', 'low', {
    authentication: 'unclear', impact: 'information disclosure', reviewDepth: 'official-advisory-private-details',
    rationale: 'The record says unauthorized but does not disclose a route, request, or whether the response is on a CORS-readable API surface.',
  }),
  'CVE-2026-15975': assessment('likely-compatible', 'low', {
    authentication: 'none', impact: 'denial of service', reviewDepth: 'official-advisory-private-details',
    prerequisites: ['Exact merge-request discussion route and request pattern are private'],
    rationale: 'Unauthenticated repeated HTTP processing is likely browser-sendable, but the public record lacks the route needed for confirmation.',
  }),
  'CVE-2026-3160': assessment('outside-threat-model', 'high', {
    authentication: 'required', impact: 'information disclosure', rationale: 'The official description requires an authenticated user and Jira integration context.',
  }),
  'CVE-2026-1659': assessment('unresolved', 'low', {
    route: 'CI/CD job update API', authentication: 'none', impact: 'denial of service', reviewDepth: 'official-advisory-private-details',
    prerequisites: ['The exact API path, request method, and triggering payload remain private'],
    rationale: 'The named surface is an API, but the per-CVE XDB query returned no exploit repository to grep for an exact /api route or browser-compatible request.',
  }),
  'CVE-2026-1092': assessment('unresolved', 'low', {
    route: 'Terraform state lock API', method: 'JSON request', authentication: 'none', impact: 'denial of service', reviewDepth: 'official-advisory-private-details',
    prerequisites: ['The exact API path and triggering JSON quantity remain private'],
    rationale: 'The named surface is an API and JSON is browser-generable, but the per-CVE XDB query returned no exploit repository to grep for an exact /api route or CORS-compatible trigger.',
  }),
  'CVE-2025-13929': assessment('likely-compatible', 'medium', {
    route: 'repository archive endpoint', method: 'GET or POST unknown', authentication: 'none', browserMechanism: 'cross-origin request',
    responseReadable: false, impact: 'denial of service', reviewDepth: 'official-advisory-private-details',
    rationale: 'Unauthenticated repository archive endpoints are ordinary HTTP routes and likely browser-callable; exact triggering parameters remain private.',
  }),
  'CVE-2026-1102': assessment('outside-threat-model', 'high', {
    route: 'SSH authentication', authentication: 'none', browserMechanism: 'not available to browser fetch', impact: 'denial of service',
    rationale: 'The vulnerability requires malformed SSH authentication, not HTTP/API traffic.',
  }),
  'CVE-2025-13927': assessment('unresolved', 'low', {
    route: 'Jira Connect integration endpoint (exact route private)', authentication: 'none', impact: 'denial of service',
    reviewDepth: 'official-advisory-private-details',
    prerequisites: ['Jira Connect integration configured', 'Unknown malformed authentication-data shape and any integration signature requirements'],
    rationale: 'GitLab identifies unauthenticated malformed authentication data in Jira Connect, but the route, method, content type, and any integration-secret requirements remain private, so browser sendability is unresolved.',
  }),
  'CVE-2025-10858': assessment('unresolved', 'low', {
    method: 'large JSON upload', authentication: 'none', impact: 'denial of service', reviewDepth: 'official-advisory-private-details',
    prerequisites: ['Unknown upload route and encoding', 'Unknown minimum payload size and practical browser limits'],
    rationale: 'A browser can generate JSON, but GitLab does not disclose whether the upload uses multipart or application/json, the route and preflight behavior, or the payload size needed for impact.',
  }),
  'CVE-2025-2256': assessment('conditional-compatible', 'medium', {
    route: 'SAML callback', method: 'form POST', authentication: 'none', browserMechanism: 'simple cross-origin form submission',
    responseReadable: false, impact: 'denial of service', prerequisites: ['SAML authentication configured', 'Many concurrent large SAML responses'],
    rationale: 'SAML form posts are browser-sendable without CORS response access, but the target must have SAML configured.',
  }),
  'CVE-2025-0993': assessment('outside-threat-model', 'high', {
    authentication: 'required', impact: 'denial of service', rationale: 'The official description requires an authenticated attacker.',
  }),
  'CVE-2025-1278': assessment('unresolved', 'low', {
    authentication: 'unclear', impact: 'information disclosure', reviewDepth: 'official-advisory-private-details',
    prerequisites: ['Target group uses IP restrictions', 'A restricted issue exists and is known or guessable'],
    rationale: 'The issue-title disclosure route and mechanism are private. Exploitation in this threat model needs a CORS-readable response or another cross-origin leak, which public evidence does not establish.',
  }),
  'CVE-2025-2408': assessment('outside-threat-model', 'high', {
    route: 'GraphQL subscription', authentication: 'required', browserMechanism: 'authenticated WebSocket/ActionCable subscription',
    impact: 'information disclosure', reviewDepth: 'public-primary-reproduction', publicPoc: 'GitLab work item contains the subscription query',
    prerequisites: ['Attacker-controlled authenticated GitLab account', 'Ultimate group with IP restrictions', 'Known WorkItem global ID'],
    rationale: 'The public reproduction explicitly logs in an attacker account and uses a subscription, unlike the anonymous cross-origin fetch threat model.',
  }),
  'CVE-2024-9631': assessment('conditional-compatible', 'high', {
    route: '/:group/:project/-/commit/:sha/diff_files or merge_requests/:id/diffs_batch.json', method: 'GET',
    authentication: 'none for public project', browserMechanism: 'simple cross-origin GET', responseReadable: false,
    impact: 'denial of service', reviewDepth: 'public-primary-reproduction', publicPoc: 'GitLab work item includes routes and load procedure',
    prerequisites: ['Known public project with expensive commit or merge-request diffs', 'Repeated requests'],
    rationale: 'The public report confirms unauthenticated CPU-heavy GET routes. A browser can send these requests even though SOP blocks reading the response.',
  }),
  'CVE-2023-5117': assessment('outside-threat-model', 'medium', {
    route: 'direct uploaded-file URL', method: 'GET', authentication: 'none', browserMechanism: 'navigation or opaque fetch',
    responseReadable: false, impact: 'information disclosure', reviewDepth: 'public-primary-description',
    prerequisites: ['Exact secret attachment URL'],
    rationale: 'The flaw exposes a file to someone who already has its URL, but a hostile cross-origin page cannot read a non-CORS upload response through JavaScript.',
  }),
  'CVE-2024-8650': assessment('outside-threat-model', 'high', {
    route: '/:group/:project/-/issues/new?merge_request_to_resolve_discussions_of=:id', method: 'GET',
    authentication: 'none', browserMechanism: 'navigation or opaque fetch', responseReadable: false,
    impact: 'information disclosure', reviewDepth: 'public-primary-reproduction', publicPoc: 'GitLab work item gives the UI URL',
    rationale: 'The leak is rendered in a non-API HTML page. A cross-origin script can request it but cannot read its body under SOP/CORS.',
  }),
  'CVE-2024-8233': assessment('conditional-compatible', 'high', {
    route: '/:group/:project/-/commit/:sha/diff_files and merge_requests/:id/diffs_batch.json', method: 'GET',
    authentication: 'none for public project', browserMechanism: 'simple cross-origin GET', responseReadable: false,
    impact: 'denial of service', reviewDepth: 'public-primary-reproduction', publicPoc: 'GitLab work item includes exact routes and reproduction',
    prerequisites: ['Known expensive public commit or merge request', 'Repeated requests'],
    rationale: 'The disclosed GET requests can be issued cross-origin without reading the response, but useful impact depends on expensive public diffs.',
  }),
  'CVE-2024-8124': assessment('confirmed-compatible', 'high', {
    route: '/users/sign_in', method: 'POST application/x-www-form-urlencoded', authentication: 'none',
    browserMechanism: 'simple cross-origin form request', responseReadable: false, impact: 'denial of service',
    reviewDepth: 'public-primary-reproduction', publicPoc: 'GitLab work item includes the form body and route',
    prerequisites: ['Very large glm_source form value', 'Multiple requests for demonstrated impact'],
    rationale: 'The public report uses an unauthenticated form-encoded POST, which is a CORS-simple browser request and does not need response access.',
  }),
  'CVE-2024-45409': assessment('outside-threat-model', 'high', {
    route: 'SAML callback', method: 'form POST', authentication: 'none', browserMechanism: 'cross-origin form submission',
    impact: 'authentication bypass', prerequisites: ['SAML configured', 'Access to a valid signed IdP document', 'Affected Ruby-SAML integration'],
    rationale: 'The default CE lab has no SAML provider. This is configuration-dependent authentication forgery, not anonymous GitLab API response access.',
  }),
  'CVE-2024-3958': assessment('outside-threat-model', 'high', {
    route: 'Git command-line clone workflow', authentication: 'none', userInteraction: true,
    browserMechanism: 'not a browser API request', impact: 'social engineering',
    rationale: 'The issue relies on a display-versus-Git discrepancy and persuading a victim to clone code.',
  }),
};

function vectorPart(vector, key) {
  return vector.split('/').find((part) => part.startsWith(`${key}:`))?.slice(key.length + 1) || null;
}

function automaticAssessment(item) {
  const vector = item.cvss.vector || '';
  const attackVector = vectorPart(vector, 'AV');
  const privileges = vectorPart(vector, 'PR');
  const interaction = vectorPart(vector, 'UI');
  const withoutUnauthenticated = item.summary.replace(/\bunauthenticated\b/gi, '');

  if (attackVector && attackVector !== 'N') {
    return assessment('outside-threat-model', 'high', {
      authentication: privileges === 'N' ? 'none' : 'required',
      rationale: `CVSS records attack vector ${attackVector}, not a network request reachable by the hostile web page.`,
      reviewDepth: 'structured-record-review',
    });
  }
  if (privileges && privileges !== 'N') {
    return assessment('outside-threat-model', 'high', {
      authentication: 'required',
      rationale: `CVSS ${item.cvss.vector} requires privileges (${privileges}); the threat model provides no GitLab token or cross-site session.`,
      reviewDepth: 'structured-record-review',
    });
  }
  if (interaction && interaction !== 'N') {
    return assessment('outside-threat-model', 'high', {
      authentication: 'unknown', userInteraction: true,
      rationale: `CVSS ${item.cvss.vector} requires user interaction; the assessed primitive is an unattended cross-origin request.`,
      reviewDepth: 'structured-record-review',
    });
  }
  if (/\bauthenticated\b/i.test(withoutUnauthenticated)) {
    return assessment('outside-threat-model', 'medium', {
      authentication: 'required',
      rationale: 'The official description explicitly requires an authenticated user despite the selected CVSS metric indicating no privileges.',
      reviewDepth: 'official-advisory-review',
    });
  }
  return assessment('unresolved', 'low', {
    authentication: privileges === 'N' ? 'none' : 'unknown',
    rationale: 'The public structured record does not disclose enough route and request detail to prove or exclude compatibility with a hostile browser request.',
    reviewDepth: 'structured-record-review',
  });
}

if (refreshXdb || refreshXdbUncertain) {
  const items = refreshXdbUncertain
    ? catalog.vulnerabilities.filter((item) =>
        (overrides[item.id] || automaticAssessment(item)).status === 'unresolved')
    : catalog.vulnerabilities;
  await refreshVulnCheckXdb(items);
}

// Also apply newly added reviews to an already refreshed catalog.
for (const item of catalog.vulnerabilities) {
  for (const match of item.vulnCheckXdb?.matches || []) {
    match.sourceReview = reviewedXdbSource(match.id, match.sourceReview || null);
  }
}

for (const item of catalog.vulnerabilities) {
  const manuallyReviewed = Object.hasOwn(overrides, item.id);
  const result = overrides[item.id] || automaticAssessment(item);
  const gitlabEvidence = item.links?.gitlab || [];
  const publicPrimaryReproduction = result.reviewDepth === 'public-primary-reproduction';

  item.browserApiAssessment = {
    ...result,
    evidenceNotes: [
      ...result.evidenceNotes,
      ...(result.status === 'unresolved' && item.vulnCheckXdb?.checkedAt && !item.vulnCheckXdb.matches.length
        ? [`VulnCheck XDB returned no repository for the exact ${item.id} query at ${item.vulnCheckXdb.checkedAt}; absence is not evidence of non-exploitability.`]
        : []),
    ],
    likelihood: likelihoodByStatus[result.status],
    reviewMode: manuallyReviewed ? 'manual-candidate-review' : 'structured-threat-model-exclusion',
    manuallyReviewed,
    evidenceUrls: [...new Set([
      item.links?.nvd,
      item.links?.cve,
      ...gitlabEvidence,
      item.vulnCheckXdb?.queryUrl || xdbApiUrl(item.id),
      ...(item.vulnCheckXdb?.matches || []).map((entry) => entry.url),
    ].filter(Boolean))],
    publicPocUrl: publicPrimaryReproduction
      ? gitlabEvidence.find((url) => /gitlab\.com\/gitlab-org\/gitlab\/-\/(issues|work_items)\//.test(url)) || null
      : null,
    pocEvidenceState: publicPrimaryReproduction
      ? 'public-primary-reproduction-reviewed'
      : result.reviewDepth === 'official-advisory-private-details'
        ? 'primary-details-private-or-not-publicly-retrievable'
        : manuallyReviewed
          ? 'public-advisory-and-available-primary-links-reviewed'
          : 'not-required-to-establish-explicit-threat-model-blocker',
  };
}

const missingAssessments = catalog.vulnerabilities.filter((item) =>
  !item.browserApiAssessment?.status || !item.browserApiAssessment?.rationale,
);
if (missingAssessments.length) {
  throw new Error(`Incomplete browser/API assessments: ${missingAssessments.map((item) => item.id).join(', ')}`);
}

catalog.browserThreatModel = {
  version: 2,
  description: 'Attacker-controlled public web page reaching an internal GitLab through an Edge 131-class browser.',
  assumptions: [
    'No stolen GitLab token and no attacker knowledge of victim credentials.',
    'No ambient cross-site GitLab session cookie is assumed.',
    'Edge 131 default Private Network Access warnings are not enforced.',
    'GitLab /api/* and /api/graphql wildcard CORS responses are readable without credentials.',
    'Simple cross-origin GET/form requests may be sent even when their non-API responses are not readable.',
  ],
  statuses: {
    'confirmed-compatible': 'Public primary reproduction establishes a browser-sendable trigger under this threat model.',
    'likely-compatible': 'Official evidence strongly indicates compatibility, but exact primary reproduction details are unavailable.',
    'conditional-compatible': 'Browser-call compatible only when listed content, configuration, identifiers, or scale prerequisites exist.',
    unresolved: 'Public evidence is insufficient to decide.',
    'outside-threat-model': 'An explicit prerequisite or transport is outside this anonymous hostile-page model.',
  },
  methodology: 'Every record receives a structured review. Anonymous network candidates not excluded by privileges, interaction, or transport are marked as manually reviewed only when a CVE-specific override records route, prerequisite, response-readability, and public-primary-reproduction findings; remaining candidates stay unresolved and are counted as pending manual review. Explicit privilege, interaction, and non-network blockers are classified from CVSS plus the official description. VulnCheck XDB is queried separately for every CVE; repository presence is supporting evidence, while sourceReview records whether the linked implementation was actually inspected. Outside-threat-model does not mean non-exploitable generally.',
  reviewedAt,
};

catalog.assessmentSummary = Object.entries(
  Object.groupBy(catalog.vulnerabilities, (item) => item.browserApiAssessment.status),
).map(([status, items]) => ({ status, count: items.length }));

catalog.assessmentCoverage = {
  totalRecords: catalog.vulnerabilities.length,
  manuallyReviewedRecords: catalog.vulnerabilities.filter((item) => item.browserApiAssessment.manuallyReviewed).length,
  structuredThreatModelExclusions: catalog.vulnerabilities.filter((item) => item.browserApiAssessment.reviewMode === 'structured-threat-model-exclusion').length,
  publicPrimaryReproductionsReviewed: catalog.vulnerabilities.filter((item) => item.browserApiAssessment.pocEvidenceState === 'public-primary-reproduction-reviewed').length,
  privateOrUnavailablePrimaryDetails: catalog.vulnerabilities.filter((item) => item.browserApiAssessment.pocEvidenceState === 'primary-details-private-or-not-publicly-retrievable').length,
  unresolvedRecords: catalog.vulnerabilities.filter((item) => item.browserApiAssessment.status === 'unresolved').length,
  pendingManualCandidateReviews: catalog.vulnerabilities.filter((item) =>
    item.browserApiAssessment.status !== 'outside-threat-model' && !item.browserApiAssessment.manuallyReviewed
  ).length,
  xdbRecordsChecked: catalog.vulnerabilities.filter((item) => item.vulnCheckXdb?.checkedAt).length,
  xdbRecordsWithMatches: catalog.vulnerabilities.filter((item) => item.vulnCheckXdb?.matches?.length).length,
  xdbRepositoriesFound: catalog.vulnerabilities.reduce((total, item) => total + (item.vulnCheckXdb?.matches?.length || 0), 0),
  xdbRepositoriesSourceReviewed: catalog.vulnerabilities.reduce((total, item) =>
    total + (item.vulnCheckXdb?.matches || []).filter((entry) => entry.sourceReview?.reviewedAt).length, 0),
};

checkpointCatalog();
console.log(JSON.stringify({
  summary: catalog.assessmentSummary,
  coverage: catalog.assessmentCoverage,
}));
