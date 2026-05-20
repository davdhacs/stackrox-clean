#!/usr/bin/env bash
# shellcheck disable=SC1091
set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"

if [[ "${USE_ROXIE_DEPLOY:-false}" == "true" ]]; then
    ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd)"
    cat <<EOF
----------------------------------------------------------------------------------------
Using roxie to deploy StackRox. 🎉
If this is not intended, please unset USE_ROXIE_DEPLOY and re-run the deployment script.

roxie will deploy StackRox and then spawn a sub-shell for you to interact with central.

For tearing down the deployment, invoke:
  ${ROOT}/scripts/teardown.sh
----------------------------------------------------------------------------------------

EOF

    "${ROOT}/scripts/roxie.sh" deploy --single-namespace "$@"
    exit $?
fi

cat <<EOF
-------------------------------------------------------------------------------------
USE_ROXIE_DEPLOY not enabled, using kubectl to deploy StackRox
Please consider setting USE_ROXIE_DEPLOY=true and opting into roxie-based deployments
-------------------------------------------------------------------------------------
EOF

# shellcheck source=./detect.sh
source "${DIR}/detect.sh"

if is_openshift; then
    source "${DIR}/openshift/deploy.sh"
else
    source "${DIR}/k8s/deploy.sh"
fi
