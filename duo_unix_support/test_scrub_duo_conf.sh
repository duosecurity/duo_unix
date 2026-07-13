#!/usr/bin/env bash
#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Regression tests for scrub_duo_conf in duo_unix_support.sh.
# Sources the function directly from the shipping script.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${SCRIPT_DIR}/duo_unix_support.sh"

if [ ! -f "${COLLECTOR}" ]; then
    echo "cannot find duo_unix_support.sh next to test" >&2
    exit 2
fi

FN_TMP="$(mktemp)"
trap 'rm -f "${FN_TMP}"' EXIT

awk '
    /^scrub_duo_conf \(\) \{$/ { in_fn = 1 }
    in_fn { print }
    in_fn && /^\}$/ { exit }
' "${COLLECTOR}" > "${FN_TMP}"

if ! grep -q '^scrub_duo_conf ()' "${FN_TMP}"; then
    echo "failed to extract scrub_duo_conf from ${COLLECTOR}" >&2
    exit 2
fi

# shellcheck source=/dev/null
. "${FN_TMP}"

PASS=0
FAIL=0
TMP="$(mktemp -d)"
trap 'rm -f "${FN_TMP}"; rm -rf "${TMP}"' EXIT

# assert_scrub NAME INPUT FORBIDDEN_REGEX [REQUIRED_REGEX...]
assert_scrub () {
    local name="$1" ; shift
    local input="$1" ; shift
    local forbidden="$1" ; shift

    local src="${TMP}/${name}.in"
    local dst="${TMP}/${name}.out"
    printf '%s' "${input}" > "${src}"

    if ! scrub_duo_conf "${src}" "${dst}"; then
        printf 'FAIL %s: scrub_duo_conf returned non-zero\n' "${name}" >&2
        FAIL=$((FAIL + 1))
        return
    fi

    local perm
    if perm=$(stat -c '%a' "${dst}" 2>/dev/null); then :
    else perm=$(stat -f '%Lp' "${dst}"); fi
    if [ "${perm}" != "600" ]; then
        printf 'FAIL %s: expected mode 600, got %s\n' "${name}" "${perm}" >&2
        FAIL=$((FAIL + 1))
        return
    fi

    if [ -n "${forbidden}" ] && grep -qE "${forbidden}" "${dst}"; then
        printf 'FAIL %s: forbidden regex %q matched in output:\n' "${name}" "${forbidden}" >&2
        sed 's/^/    /' "${dst}" >&2
        FAIL=$((FAIL + 1))
        return
    fi

    while [ "$#" -gt 0 ]; do
        if ! grep -qE "$1" "${dst}"; then
            printf 'FAIL %s: expected regex %q not found in output:\n' "${name}" "$1" >&2
            sed 's/^/    /' "${dst}" >&2
            FAIL=$((FAIL + 1))
            return
        fi
        shift
    done

    PASS=$((PASS + 1))
    printf 'ok   %s\n' "${name}"
}

assert_scrub baseline "$(cat <<'CONF'
[duo]
ikey = DIXXXXXXXXXXXXXXXXXX
skey = REPLACE_ME_SKEY
host = api-example.duosecurity.com
http_proxy = http://user:pw@proxy.example.com:3128
CONF
)" 'REPLACE_ME_SKEY|user:pw|^skey' \
   '^http_proxy = http://REDACTED@proxy\.example\.com:3128$' \
   '^ikey = DIXXXXXXXXXXXXXXXXXX$'

assert_scrub slash_in_pw "$(cat <<'CONF'
[duo]
http_proxy = http://user:my/password@proxy.example.com:3128
CONF
)" 'my/password' \
   '^http_proxy = http://REDACTED@proxy\.example\.com:3128$'

assert_scrub at_in_pw "$(cat <<'CONF'
[duo]
http_proxy = http://user:p@ss@proxy.example.com:3128
CONF
)" 'p@ss@|:p@ss' \
   '^http_proxy = http://REDACTED@proxy\.example\.com:3128$'

assert_scrub ipv6_host "$(cat <<'CONF'
[duo]
http_proxy = http://user:pw@[::1]:3128
CONF
)" 'user:pw@' \
   '^http_proxy = http://REDACTED@\[::1\]:3128$'

assert_scrub schemeless "$(cat <<'CONF'
[duo]
http_proxy = user:pw@proxy.corp:3128
CONF
)" 'user:pw' \
   '^http_proxy = REDACTED@proxy\.corp:3128$'

assert_scrub mixed_case_scheme "$(cat <<'CONF'
[duo]
http_proxy = HTTP://User:Pass@Proxy.Example.COM:3128
CONF
)" 'User:Pass' \
   '^http_proxy = HTTP://REDACTED@Proxy\.Example\.COM:3128$'

assert_scrub inline_semicolon_comment "$(cat <<'CONF'
[duo]
ikey = DIXXXX ; skey backup: 4MjRQ2NmRiM2Q1Y
host = api-example.com  ; internal notes: PW
CONF
)" '4MjRQ2NmRiM2Q1Y|PW|skey backup|internal notes' \
   '^ikey = DIXXXX$' \
   '^host = api-example\.com$'

assert_scrub section_header_junk "$(cat <<'CONF'
[duo] skey = INSIDE_SECTION_HEADER
[duo]
ikey = ABC
CONF
)" 'INSIDE_SECTION_HEADER' \
   '^ikey = ABC$'

assert_scrub hyphenated_names "$(cat <<'CONF'
[duo]
verified-push = yes
duo.host = api.example.com
ikey = DIABC
CONF
)" 'verified-push|duo\.host' \
   '^ikey = DIABC$' \
   '2 option\(s\).*were dropped'

assert_scrub no_dev_fips_mode "$(cat <<'CONF'
[duo]
ikey = DIABC
dev_fips_mode = 1
CONF
)" '^dev_fips_mode' \
   '^ikey = DIABC$' \
   '1 option\(s\).*were dropped'

assert_scrub skey_dropped "$(cat <<'CONF'
[duo]
skey = LEAKED
ikey = KEPT
CONF
)" '^skey|LEAKED' \
   '^ikey = KEPT$'

assert_scrub skey_multiline_continuation_dropped "$(cat <<'CONF'
[duo]
ikey = DIABC
skey =
    REPLACE_ME_SKEY_ON_CONTINUATION
host = api-example.com
CONF
)" 'REPLACE_ME_SKEY_ON_CONTINUATION|^skey' \
   '^ikey = DIABC$' \
   '^host = api-example\.com$'

assert_scrub quoted_url_credentials_gone "$(cat <<'CONF'
[duo]
http_proxy = "http://alice:PW@proxy.example.com:3128"
CONF
)" 'alice:PW|alice|PW'

assert_scrub path_query_preserves_host "$(cat <<'CONF'
[duo]
http_proxy = http://user:pw@proxy.example.com:3128/?token=abc@xyz
CONF
)" 'user:pw' \
   '^http_proxy = http://REDACTED@proxy\.example\.com:3128/\?token=abc@xyz$'

assert_scrub hash_in_group_pattern_preserved "$(cat <<'CONF'
[duo]
groups = admins #devops
CONF
)" '' \
   '^groups = admins #devops$'

assert_scrub skey_in_comment_dropped "$(cat <<'CONF'
# backup skey: 4MjRQ2NmRiM2Q1Y
[duo]
ikey = DIABC
; old_skey_note: this rotated 2024-01-01
host = api.example.com
CONF
)" '4MjRQ2NmRiM2Q1Y|old_skey_note' \
   '^ikey = DIABC$' \
   '^host = api\.example\.com$'

assert_scrub crlf_endings "$(printf '[duo]\r\nikey = DIABC\r\nskey = LEAKED\r\n')" \
   'LEAKED' \
   '^ikey = DIABC'

assert_scrub trailing_whitespace "$(printf '[duo]\nikey = DIABC   \n')" \
   'DIABC   $' \
   '^ikey = DIABC$'

echo
echo "passed: ${PASS}, failed: ${FAIL}"
[ "${FAIL}" -eq 0 ]
