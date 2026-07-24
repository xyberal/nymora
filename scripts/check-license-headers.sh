#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# nymora's OWN check (ships publicly): every Rust source file must carry the SPDX header.
# Runs from the nymora/ workspace root (which becomes the public repo root after split).
set -euo pipefail

cd "$(dirname "$0")/.."   # nymora/ workspace root

required="SPDX-License-Identifier: MIT OR Apache-2.0"
missing=0

while IFS= read -r -d '' f; do
    if ! head -n 3 "$f" | grep -q "$required"; then
        echo "missing SPDX header: $f"
        missing=1
    fi
done < <(find . -name '*.rs' -not -path './target/*' -print0)

if [ "$missing" -ne 0 ]; then
    echo "license-header check FAILED"
    exit 1
fi
echo "license-header check passed"
