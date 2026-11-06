#!/bin/sh
set -eu

base_url="${1:-http://127.0.0.1:8929}"
origin="${2:-https://attacker.example}"

request() {
  label="$1"
  shift
  printf '\n### %s\n' "$label"
  curl --silent --show-error --dump-header - --output /dev/null "$@" \
    | tr -d '\r' \
    | sed -n -E '/^(HTTP\/|access-control-|vary:|set-cookie:|x-frame-options:|content-security-policy:)/Ip'
}

request "Cross-origin API GET" \
  -H "Origin: $origin" \
  "$base_url/api/v4/version"

request "Cross-origin public API GET" \
  -H "Origin: $origin" \
  "$base_url/api/v4/projects?visibility=public&per_page=1"

request "CORS preflight" \
  -X OPTIONS \
  -H "Origin: $origin" \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Access-Control-Request-Headers: private-token' \
  "$base_url/api/v4/version"

request "Private Network Access preflight" \
  -X OPTIONS \
  -H "Origin: $origin" \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Access-Control-Request-Private-Network: true' \
  "$base_url/api/v4/version"

request "Cross-origin non-API GET" \
  -H "Origin: $origin" \
  "$base_url/users/sign_in"

