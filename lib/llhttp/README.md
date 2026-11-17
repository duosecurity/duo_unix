<!--
SPDX-License-Identifier: MIT

Copyright Fedor Indutny, 2018.
-->

# Vendored llhttp

HTTP response parser used by `lib/https.c`. It replaces the archived Joyent
`http_parser` v1.0 that was previously vendored in `lib/`.

| Field     | Value                                                                    |
|-----------|--------------------------------------------------------------------------|
| Component | llhttp                                                                   |
| Upstream  | https://github.com/nodejs/llhttp                                         |
| Version   | 9.4.3 (tag `release/v9.4.3`, published 2026-07-30)                        |
| Archive   | https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.4.3.tar.gz |
| SHA-256   | `1eb813c7437b31a87496a1cd3ed79f00746720f5e7e29c79b42c02cb69f36c39`       |
| License   | MIT (see `LICENSE-MIT`)                                                  |

## Files

| Here         | Upstream (release archive) |
|--------------|----------------------------|
| `llhttp.h`   | `include/llhttp.h`         |
| `llhttp.c`   | `src/llhttp.c`             |
| `api.c`      | `src/api.c`                |
| `http.c`     | `src/http.c`               |
| `LICENSE-MIT`| `LICENSE-MIT`              |

The only local change is an SPDX comment block at the top of each source
file. Everything below it is byte-for-byte identical to upstream.

## Updating

1. Download the `release/vX.Y.Z` archive from the URL pattern above. Take it
   from the `release/*` tag, which ships the generated C; the `main` branch
   only has the TypeScript sources.
2. Copy the four files listed above over the existing copies, keeping the
   SPDX header and updating the version it mentions.
3. Update the version, archive URL and SHA-256 in this file.
4. Run `make check`. `tests/unity_tests/http_response_parse_test.c` covers
   the Duo API response shapes we depend on.
