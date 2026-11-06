# GitLab default CORS and Local Network Access findings

Tested against a running `gitlab/gitlab-ce` container pinned for the lab and
published on the host loopback interface only. The CORS behaviour below is the
GitLab default and is not specific to any one patch release.

## Observed GitLab behaviour

- `/api/*` accepts cross-origin requests from an arbitrary origin and responds
  with `Access-Control-Allow-Origin: *`.
- Its preflight permits `GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS` and
  reflects requested headers such as `Private-Token`.
- The CORS middleware explicitly sets `credentials: false` for the wildcard
  origin. It therefore does not grant a public origin credentialed, readable
  access using the GitLab session cookie.
- A public API request was both sent and readable cross-origin (`200`, body
  `[]`). An endpoint requiring authentication returned `401` while still
  carrying the wildcard CORS headers.
- Non-API pages such as `/users/sign_in` did not return an
  `Access-Control-Allow-Origin` header.
- A Private Network Access style preflight (the mechanism Chrome tried before
  Local Network Access) was accepted as an ordinary CORS preflight, but the
  response did **not** contain `Access-Control-Allow-Private-Network: true`.

The installed Rails middleware confirms this is intentional: it permits the
configured GitLab origin with credentials and separately permits `*` for
`/api/*` without credentials.

Raw captured response headers are in `results/cors-headers.txt` and
`results/public-projects.headers`.

## Local Network Access implication

Browsers without Local Network Access enforcement (Firefox, Safari, Chrome before
142, or Chrome with the control turned off by policy) do not block a public site
from sending a request to an internal host. There, a public site can cause the
browser to send a request to an internal GitLab, and GitLab's opt-in header is
irrelevant. Chrome 142 and later instead ask the visitor for a local network
permission before a public page reaches a private or loopback address. A
request from a page that is itself on the internal network is local-to-local and
is not gated.

That does not by itself supply authentication or defeat GitLab authorization:

- JavaScript can read public API responses because GitLab deliberately uses a
  wildcard origin.
- JavaScript cannot read a credentialed response under wildcard CORS.
- A private token would have to be known to the public site before it could put
  the token in the CORS-approved `Private-Token` header.
- A request being sent is still relevant to CSRF and side-effecting endpoints,
  but exploitability then depends on cookie SameSite behaviour, CSRF validation,
  endpoint semantics, and the prerequisites of the specific CVE.

## Fingerprinting: client-side resolution is a build class, not a patch

Two channels are observable from an attacker-origin page against a default
instance: content-hashed asset presence (`<link rel=preload>`/`<img>` load vs
404, no CORS needed) and the anonymous GraphQL Query-schema (readable via the
`/api/*` wildcard CORS). The page uses asset presence for matching; the schema
SHA is recorded but not yet in the corpus, so it does not take part. `/assets/webpack/manifest.json` returns 200 but
carries no `Access-Control-Allow-Origin` header, so its body is not readable
cross-origin; `metadata { version }` over GraphQL is `null` without auth.

Extracting the Webpack manifest from the `gitlab/gitlab-ce` and
`gitlab/gitlab-ee` image filesystems (no boot required) shows that patch releases
often share a byte-identical asset-name set and Webpack hash: those patches
changed only backend code. So unauthenticated client-side fingerprinting resolves
to the **frontend build shared by a range of releases**, not a single patch. The
exact patch requires the authenticated `/api/v4/version` endpoint.

The full per-patch corpus bears this out: every `-ce.0` and `-ee.0` manifest
from 10.0.0 to 19.5.3 (1,927 manifests) deduplicates to 1,107 build classes
(under two patches per build on average, so builds change roughly every other
patch, far finer than per-minor). Each build's probe set is proven not to be a
subset of any other, and every manifest resolves to its own build in simulation,
so no two corpus builds can be confused. A patch released after collection can
match the newest collected patch of its minor line, so the page keeps that later
patch as a candidate.

Verified live against real instances across the range (community and
enterprise, 16.x to 19.5): the bundled content-hashed probes return 200, and a
random-hash control probe returns 404 (the page refuses to fingerprint a server
that answers it). Pointed at a non-GitLab origin the page reports that no GitLab
was recognised and shows no version or CVE list, rather than guessing.

### Turning a build class into a vulnerability verdict

The question the tool answers is "is this instance vulnerable", so each CVE is
classified against the build class's full patch list, not a single version:
vulnerable in **every** patch of the class → VULNERABLE; vulnerable in **some**
→ MAYBE (a fix lands on a patch that is client-side indistinguishable, never
silently treated as safe); vulnerable in **none** → fixed. An authenticated
`/api/v4/version` token collapses every MAYBE to a definite verdict.
