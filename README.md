# GitLab drive-by CORS exposure scanner

A single web page that, when a victim opens it in their browser, fingerprints an
internal GitLab they can reach, tells you which CVEs that version is exposed to,
and flags which of those might be reached from the attacker's page itself with no
GitLab login. 

It is a drive-by: the victim has to open the page (and, on recent
Chrome against an internal address, accept a local-network permission prompt). 

This project is open source, it deliberately never phones home, and everything it needs ships in
the page.

## Why this matters

Lots of organisations run GitLab as the internal, free alternative to GitHub,
and assume that putting it behind a VPN or an IP allowlist keeps it safe. That
assumption is the gap.

By default GitLab answers cross-origin requests to `/api/*` from **any** origin,
with `Access-Control-Allow-Origin: *`. So a page on `evil.com` can reach
`git.internal.example` through the browser of anyone who visits `evil.com`. They
do not log in. Their browser is the bridge from the attacker's public page to the
internal host.

- A GitLab on a public IP protected only by an IP allowlist is reachable this way:
  the request comes from the victim's allowlisted browser, not from the attacker.
  The attacker sees what an anonymous user inside the allowlist would see, which is
  enough to fingerprint the version.
- Browsers without Local Network Access enforcement let a public page talk to a
  private-address (RFC 1918) host, so an internal GitLab is reachable through a
  victim on the inside. Chrome 142 and later (enforced from 28 October 2025) gate
  that public-to-private hop behind a permission prompt, so against an internal
  target on an up-to-date Chrome it needs one click (the visitor must click Allow).
  That control does not apply to a GitLab on a public IP (a public-to-public
  request is never gated), nor to Firefox or Safari, nor to older Chrome or Chrome
  where an administrator has turned it off. Nor does it apply when the hostile page
  is itself served from the internal network, such as a compromised wiki or
  SharePoint page, because that request is local-to-local.
- The page tells these cases apart. It reports "API closed" only when a known
  GitLab asset loaded from the address, so a browser block, an unreachable host or
  a server that is not GitLab is never reported as closed.

This tool demonstrates the exposure concretely and turns it into a prioritised,
evidence-backed list rather than a theory.

## The CORS route, precisely

Measured live against a default GitLab (see [FINDINGS.md](FINDINGS.md) for the
captured headers):

- `/api/*` and `/api/graphql` return `Access-Control-Allow-Origin: *` **without**
  credentials. Anonymous JSON responses there are therefore **readable**
  cross-origin by any page. This is what makes fingerprinting and reading public
  API data possible from `evil.com`.
- The wildcard is set with `credentials: false`, so even where a browser attaches
  the victim's GitLab session cookie, the attacker's page cannot **read** a
  credentialed response. What it can read is anonymous data, not the victim's
  authenticated session. That boundary matters and the tool
  respects it: it never claims a CVE is reachable when the real trigger needs the
  victim's login.
- Simple cross-origin requests can still be **sent** to non-`/api` routes even
  though their responses are not readable, which is the classic CSRF-style
  side-effect channel and is relevant to some CVEs.
- `/assets/webpack/manifest.json` returns `200` but carries **no** CORS header,
  so its body is not readable cross-origin. The fingerprint never relies on it at
  runtime.

So the readable, anonymous, cross-origin surface the page uses is `/api/*` plus
asset presence. (GitLab also sends wildcard CORS on a few OAuth and OpenID
discovery endpoints, which the page does not use.)

## What the page shows

It is a guided walkthrough that reveals itself step by step. Nothing runs until
you enter an address; each stage appears only once the one before it succeeds, so
you never see a CVE list for an instance that was never fingerprinted.

### 1. It proves the CORS channel and fingerprints the version

Enter a GitLab origin and it runs a set of harmless probes. It shows the public
REST API answering cross-origin (`200`, readable), the version endpoint answering
cross-origin but requiring a token (`401`, still readable), and then the build
fingerprint it derived with no phone-home. A typical result reads "GitLab 18.11.12
to 18.11.14 (enterprise, shared frontend build)": the asset hashes match a
frontend that those three patch releases all shipped (see the resolution note
below).

If the instance's API does **not** answer cross-origin reads, the page says so and
stops. That closes the readable channel, but it is not a clean bill of health: the
version can still be fingerprinted from asset presence, and blind triggers that
never read a response are not stopped by CORS. The page spells this out. If
nothing answered at all, or something answered that is not a recognisable GitLab,
it says that instead and makes no claim either way.

### 2. It lists every CVE the detected version is exposed to

Only once a version is identified does it reveal the exposure. For the detected
build it renders every matching CVE, each marked **VULNERABLE** or
**INDETERMINATE** (shown on the page as MAYBE), with CVSS, severity, and links
out to NVD, CVE.org, the VulnCheck XDB PoC query, and the GitLab advisory.

### 3. It flags which of those are reachable from a hostile web page

Toggle to the anonymous hostile-page threat model and the list collapses to the
CVEs with a plausible anonymous browser path, each flagged BROWSER PATH: PUBLIC
REPRO, LIKELY or CONDITIONAL.

**None of these paths has been tested from a browser.** They come from reviewing
the public advisories, GitLab issues and public PoC repositories. "Public repro"
means a manual review found a public reproduction whose trigger a browser could
send; it does not mean the exploit was run through this route. Records reviewed
only with agent assistance are capped at "likely", and each row's tooltip says
which kind of review it had. Each flagged CVE
records its route, method, whether the response is readable, and any prerequisite
(a feature enabled, content seeded, an id known). `Outside threat model` means
only that this specific anonymous-browser lens does not reach it; it does not mean
the CVE is harmless in general.

## How the fingerprint works, and what it can and cannot resolve

The page uses only the two cross-origin-readable channels, and nothing else:

1. **Asset presence.** GitLab ships Webpack chunks whose filenames embed a content
   hash (`main.4e9cbf4e.chunk.js`). The page requests a bundled set of these paths
   as preload resources and watches load versus error (HTTP 200 versus 404). This
   needs no CORS because only presence is observed, never content, and the assets
   are never executed. A random-hash control probe runs first: if the server
   answers a made-up asset path (a catch-all page or proxy), the page refuses to
   fingerprint. A full match of content-hashed paths identifies a specific
   **frontend build**. Every collected build is told apart from every other, but a
   patch released after the corpus was collected can serve the same assets as the
   newest collected patch of its minor line. So when the match is the newest
   collected build of one of the three newest minor lines (the ones GitLab still
   patches), a later patch of that minor is kept as a candidate, and a CVE fixed
   in such a patch reads INDETERMINATE rather than VULNERABLE.
2. **GraphQL Query-schema SHA.** `/api/graphql` sends the wildcard CORS header, so
   the sorted anonymous Query-type field names are readable. The page records
   their SHA for reference; the corpus does not carry it yet, so it is not used in
   matching.

The discriminator for each build is a content-hashed `runtime` chunk, unique per
build. The page probes those newest-first, a few at a time, and stops at the first
hit, then confirms the full asset set of that one candidate. For a recent version
this keeps a real remote instance to a few dozen probes (older versions sit
further down the list and need more), instead of firing
the whole corpus at once and saturating the browser's per-host connection limit.
Verified against live instances across 16.x to 19.5, community and enterprise.

**Resolution limit (verified, and deliberately not hidden).** Some patch releases
ship a byte-identical frontend because the patch was backend only, so several
consecutive patch releases can carry exactly the same Webpack assets.
Unauthenticated client-side fingerprinting therefore resolves to a **build
class**, the exact set of patches that share one frontend, not always a single
patch. The exact patch is available only from the authenticated `/api/v4/version`
endpoint, so the page accepts an optional admin-approved read-only token. The
token is sent only to a host you confirm: entering it shows the normalised target
with a tick box, the tick clears whenever the address changes, and nothing runs on
its own while a token is entered. A plain-HTTP target gets a warning that the token
would cross the network unencrypted.

## Is this instance vulnerable? (the point of the tool)

Each CVE is classified against the **full patch list of the detected build**:

- **VULNERABLE**: unpatched in every patch that shares this build, so the instance
  is vulnerable whichever patch it is.
- **INDETERMINATE**: a fix lands on a patch inside the build class, so whether the
  instance is affected depends on the exact patch, which is indistinguishable
  client-side. Shown so it is never silently treated as safe.
- (fixed in every patch of the build is hidden by default; the filter shows all
  states.)

Edition matters too. NVD records GitLab CE and EE separately (the CPE
`sw_edition` field), and the detected edition (from the fingerprint, or from
`/api/v4/version`) is matched against it. An EE-only CVE is listed for an EE build
and never for a CE one. A CE entry also applies to EE, because EE is built on the
full CE codebase and NVD's EE ranges sometimes lag the CE ones for the same
advisory. If the edition cannot be determined, EE-only CVEs are shown as
INDETERMINATE rather than guessed.

With a token (one exact version, and the edition where the API reports it) every
CVE becomes definite: VULNERABLE, or fixed (hidden by default).

The ranges come from NVD's CPE data, which has errors. Where a record contradicts
GitLab's own advisory text (a typo such as 16.111.4, a missing range, an inverted
bound, or an EE-only advisory carrying CE entries), `poc/cves/errata.json`
corrects it, quoting the advisory (or GitLab's own CVE record where the advisory
gives no fix version). The NVD original is kept on the record, and the
row tooltip shows the correction. Other NVD errors may remain.

`node --test tests/*.test.mjs` runs the applicability fixtures against the logic
exactly as it ships in `poc/index.html`.

## The corpus

The bundled `poc/fingerprints.json` is generated from a per-patch corpus of real
release images: every `gitlab/gitlab-ce` and `gitlab/gitlab-ee` release from
10.0.0 to 19.5.3 (1,927 patch manifests), deduplicated into 1,107 distinct frontend
build classes. Each build's probe set is proven not to be a subset of any other
collected build, and all 1,927 manifests resolve to their own build in simulation,
so no two collected builds can be confused. Releases after the collection date are
handled as described above.

## Running it

Start the pinned lab (GitLab CE 16.0.0, loopback only, intentionally obsolete and
not to be exposed to any network):

```sh
docker compose up -d
docker compose ps
./probe-cors.sh
```

Serve the page on a different origin and open it:

```sh
python3 -m http.server 8000 --directory poc
```

Then open <http://127.0.0.1:8000/> and enter a GitLab origin (for the lab,
`http://127.0.0.1:8929`), then press Enter. Nothing is probed while you type.
Stop the lab with `docker compose down`.

### Building the single self-contained page

The published artefact is one file with the version corpus, the CVE catalogue and
every asset inlined, so it makes no request at runtime except the probes it fires
at the target you enter:

```sh
node scripts/build-page.mjs   # writes dist/index.html, with a self-containment check
```

The GitHub Pages workflow runs this build and publishes `dist/`. Serving `poc/`
directly (above) is the dev path: the same page fetches `fingerprints.json` and the
CVE catalogue from disk when the inlined globals are not present.

### Rebuilding or extending the corpus

The collector pulls each release image, extracts its Webpack `manifest.json` with
`docker cp` (no boot), and deletes the image immediately, so disk stays bounded;
it is resumable and safe to shard across background runs:

```sh
# version-list.txt: one tag per line, e.g. 16.0.0-ce.0
scripts/collect-corpus.sh version-list.txt ./manifests collect.log
node scripts/build-corpus.mjs poc/fingerprints.json ./manifests-ce:community ./manifests-ee:enterprise
```

The extracted manifests (about 2.7 GB) are not committed; the collector
regenerates them from the public release images.

Refresh the CVE catalogue with `scripts/update-cves.sh all`. It pulls NVD
applicability, refreshes the VulnCheck XDB PoC enrichment, regenerates the
browser/API assessments, re-applies the agent-assisted reviews kept in
`poc/cves/agent-reviews.json` and the errata in `poc/cves/errata.json`
(`scripts/apply-catalogue-fixes.mjs`), and fails if
`scripts/validate-master-catalog.mjs` finds the catalogue inconsistent.

## Scope and responsible use

This is a defensive demonstration for authorised testing of your own
infrastructure. It fingerprints and prioritises; it does not weaponise, and it
deliberately does not exfiltrate anything or contact any third party at runtime.
Use it only against GitLab instances you are authorised to assess. The findings
describe exposure under a specific anonymous-browser threat model; confirming any
single CVE still requires the usual configuration, edition, authentication, and
feature-prerequisite review.

## Disclaimer and liability

This tool fingerprints a GitLab build and lists the CVEs recorded against that
version. It is a prioritisation aid, not a verdict. None of the exploits has been
live-tested through this route, so reality may vary: an instance may have
other mitigation controls in place that this tool cannot see from the outside (for
example a browser's Local Network Access permission, which on recent Chromium can
require a visitor to allow a public-to-private request), and there may be exploits
that are unknown to us. The real exposure could therefore be
better, or worse, than what is shown here. Always confirm any individual finding
with your own configuration, edition, authentication and feature-prerequisite
review.

Pull requests are welcome: if you can improve the corpus, the CVE mapping or the
browser-reachability assessments, please contribute. The tool is provided as-is,
with no warranty of any kind. ControlPlane accepts no liability for any use of this
tool, or for any decision taken on the basis of its output.

## Licence

MIT. See [LICENSE](LICENSE).

## Credit

- Research, Designed and Built by [@chrisns](https://github.com/chrisns)
- Published by [ControlPlane](https://control-plane.io)
