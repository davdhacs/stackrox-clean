#!/usr/bin/env bash
set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"

"${DIR}/roxie.sh" teardown --single-namespace
