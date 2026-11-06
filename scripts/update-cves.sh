#!/bin/sh
set -eu

version="${1:-all}"
edition="${2:-community}"
if [ "$version" = "all" ]; then
  output="poc/cves/gitlab-10.0.0-and-later.json"
else
  output="poc/cves/gitlab-${version}.json"
fi
temporary="$(mktemp)"
trap 'rm -f "$temporary"' EXIT

if [ "$version" = "all" ]; then
  cpe="cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*"
  encoded_cpe="$(jq -nr --arg value "$cpe" '$value|@uri')"
  source_url="https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=${encoded_cpe}"
else
  cpe="cpe:2.3:a:gitlab:gitlab:${version}:*:*:*:${edition}:*:*:*"
  encoded_cpe="$(jq -nr --arg value "$cpe" '$value|@uri')"
  source_url="https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encoded_cpe}"
fi

mkdir -p "$(dirname "$output")"
node scripts/fetch-nvd.mjs "$source_url" "$temporary"

jq --arg version "$version" --arg edition "$edition" --arg source_url "$source_url" '
  def version_tuple($value):
    try (
      $value
      | capture("^(?<major>[0-9]+)(?:\\.(?<minor>[0-9]+))?(?:\\.(?<patch>[0-9]+))?")
      | [
          (.major | tonumber),
          ((.minor // "0") | tonumber),
          ((.patch // "0") | tonumber)
        ]
    ) catch null;
  def gitlab_matches:
    [
      .. | objects | .cpeMatch? // empty | .[]
      | select(.criteria | startswith("cpe:2.3:a:gitlab:gitlab:"))
    ];
  def reaches_version($minimum):
    (version_tuple($minimum)) as $floor
    | if .vulnerable != true then false
      elif .versionEndExcluding? then
        version_tuple(.versionEndExcluding) as $end
        | ($end == null or $end > $floor)
      elif .versionEndIncluding? then
        version_tuple(.versionEndIncluding) as $end
        | ($end == null or $end >= $floor)
      else
        (.criteria | split(":")[5]) as $criteria_version
        | version_tuple($criteria_version) as $exact
        | ($exact == null or $exact >= $floor)
      end;
  def cvss:
    if .metrics.cvssMetricV40[0] then .metrics.cvssMetricV40[0].cvssData
    elif .metrics.cvssMetricV31[0] then .metrics.cvssMetricV31[0].cvssData
    elif .metrics.cvssMetricV30[0] then .metrics.cvssMetricV30[0].cvssData
    elif .metrics.cvssMetricV2[0] then .metrics.cvssMetricV2[0].cvssData
    else {} end;
  def severity_for($metric):
    if $metric.baseSeverity then $metric.baseSeverity
    elif ($metric.baseScore // 0) >= 9 then "CRITICAL"
    elif ($metric.baseScore // 0) >= 7 then "HIGH"
    elif ($metric.baseScore // 0) >= 4 then "MEDIUM"
    elif ($metric.baseScore // 0) > 0 then "LOW"
    else "UNKNOWN" end;
  {
    schemaVersion: 2,
    product: "GitLab",
    catalogScope: (if $version == "all" then "GitLab versions 10.0.0 and later" else "Exact GitLab version" end),
    minimumVersion: (if $version == "all" then "10.0.0" else $version end),
    detectedVersion: (if $version == "all" then null else $version end),
    edition: (if $version == "all" then "all" else $edition end),
    generatedAt: now | todate,
    source: {
      name: "NIST National Vulnerability Database",
      url: $source_url,
      matching: (if $version == "all" then "Product-wide NVD CPE query filtered to vulnerable GitLab ranges intersecting version 10.0.0 or later" else "Exact NVD CPE applicability query" end)
    },
    disclaimer: (if $version == "all" then "A record is included when an NVD vulnerable GitLab CPE range intersects version 10.0.0 or later. Use its applicability ranges to test a specific version. Configuration, edition, license, authentication, and feature prerequisites still require review." else "A CPE match means the record lists this version as affected. Configuration, edition, license, authentication, and feature prerequisites still require review." end),
    vulnerabilities: [
      .vulnerabilities[].cve
      | select(.vulnStatus != "Rejected")
      | select($version != "all" or any(gitlab_matches[]; reaches_version("10.0.0")))
      | . as $cve
      | (cvss) as $metric
      | {
          id: .id,
          published: .published,
          modified: .lastModified,
          status: .vulnStatus,
          summary: ([.descriptions[] | select(.lang == "en") | .value][0] // "No English description supplied."),
          cvss: {
            version: ($metric.version // null),
            score: ($metric.baseScore // null),
            severity: severity_for($metric),
            vector: ($metric.vectorString // null)
          },
          weaknesses: ([.weaknesses[]?.description[]? | select(.lang == "en") | .value] | unique),
          applicability: ([
            gitlab_matches[]
            | {
                vulnerable,
                criteria,
                versionStartIncluding,
                versionStartExcluding,
                versionEndIncluding,
                versionEndExcluding
              }
          ] | unique),
          links: {
            nvd: ("https://nvd.nist.gov/vuln/detail/" + .id),
            cve: ("https://www.cve.org/CVERecord?id=" + .id),
            references: ([
              .references[]?
              | {url, source, tags: (.tags // [])}
            ] | unique_by(.url)),
            gitlab: ([
              .references[]?.url
              | select(test("^https://((about|docs)\\.)?gitlab\\.com/"))
            ] | unique)
          }
        }
    ] | sort_by([.published, .id]) | reverse
  }
' "$temporary" > "$output"

printf 'Wrote %s with %s CVEs\n' "$output" "$(jq '.vulnerabilities | length' "$output")"

if [ -f scripts/enrich-browser-api.mjs ]; then
  source_review_arg=""
  if [ -f poc/cves/xdb-source-reviews.json ]; then
    source_review_arg="--source-reviews=poc/cves/xdb-source-reviews.json"
  fi
  if [ "$version" = "all" ]; then
    node scripts/enrich-browser-api.mjs "$output" --refresh-xdb $source_review_arg
    # Re-apply agent-assisted reviews, the confirmed-compatible evidence bar and the
    # NVD applicability errata, then recompute the summary and coverage.
    node scripts/apply-catalogue-fixes.mjs "$output"
    node scripts/validate-master-catalog.mjs "$output" --require-xdb-complete
  else
    node scripts/enrich-browser-api.mjs "$output" --refresh-xdb $source_review_arg
  fi
fi
