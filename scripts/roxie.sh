#!/usr/bin/env bash

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
GITHUB_ROXIE_REPO="stackrox/roxie"
VERSION_FILE="${ROOT}/ROXIE_VERSION.yaml"

main() {
    local os; os=$(host_os)
    local arch; arch=$(host_arch)
    local install_path="${ROOT}/bin/${os}_${arch}/roxie"

    if ! ensure_roxie_installed "$os" "$arch" "$install_path"; then
        echo >&2 "Error: Failed to ensure roxie is installed"
        exit 1
    fi
    echo
    "$install_path" "$@"
}

host_os() {
    case "$(uname -s)" in
        Linux*)     echo "linux" ;;
        Darwin*)    echo "darwin" ;;
        *)          echo "unsupported" ;;
    esac
}

host_arch() {
    case "$(uname -m)" in
        x86_64)    echo "amd64" ;;
        arm64)     echo "arm64" ;;
        *)         echo "unsupported" ;;
    esac

}

ensure_roxie_installed() {
    local os="$1"
    local arch="$2"
    local install_path="$3"

    local version; version=$(yq eval '.version' "$VERSION_FILE")
    if [[ -z "$version" ]]; then
        echo >&2 "Error: No version found in $VERSION_FILE"
        return 1
    fi
    mkdir -p "$(dirname "$install_path")"

    local expected_checksum
    if ! expected_checksum="$(get_expected_checksum_from_version_file "$VERSION_FILE" "$os" "$arch")"; then
        return 1
    fi

    if ! exists_with_correct_checksum "$install_path" "$expected_checksum"; then
        echo "File $install_path is missing or has an incorrect checksum."
        echo "Downloading the correct version..."
        local asset_name="roxie-${os}-${arch}"
        local tmp_roxie; tmp_roxie=$(mktemp)
        gh_download_release "$tmp_roxie" "$GITHUB_ROXIE_REPO" "v${version}" "$asset_name"
        if ! verify_checksum "$tmp_roxie" "$expected_checksum"; then
            echo "Downloaded file '$tmp_roxie' has an incorrect checksum."
            rm -f "$tmp_roxie"
            return 1
        fi
        mv "$tmp_roxie" "$install_path"
        chmod +x "$install_path"
        echo "roxie ${version} has been installed to $install_path"
    fi
}

get_expected_checksum_from_version_file() {
    local version_file="$1"
    local os="$2"
    local arch="$3"
    local expected_checksum

    # yq cannot do dynamic path traversal in a safe way (without direct shell interpolation), hence
    # we use jq for that.
    expected_checksum=$(yq eval -o=json "$version_file" | jq -r --arg os "$os" --arg arch "$arch" '.[$os].[$arch] // ""')
    if [[ -z "$expected_checksum" ]]; then
        echo >&2 "Error: No checksum found in $version_file for ${os}/${arch}"
        return 1
    fi

    echo "$expected_checksum"
}

exists_with_correct_checksum() {
    local filepath="${1:-}"
    local expected_checksum="${2:-}"

    if [[ ! -e "$filepath" ]]; then
        echo "File '$filepath' does not exist"
        return 1
    fi

    local checksum; checksum="$(checksum_sha256 "$filepath")"
    if [[ "$checksum" != "$expected_checksum" ]]; then
        echo >&2 "Checksum mismatch for '$filepath'"
        echo >&2 "expected: $expected_checksum"
        echo >&2 "     got: $checksum"
        return 1
    fi

    return 0
}

# Portable wrapper for sha256 calculation.
checksum_sha256() {
    local filepath="$1"
    if command -v sha256sum &>/dev/null; then
        sha256sum "$filepath" | awk '{print $1}'
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$filepath" | awk '{print $1}'
    else
        echo >&2 "Error: neither sha256sum nor shasum found"
        return 1
    fi
}

gh_download_release() {
    local target=${1:-}
    local repo=${2:-}
    local version=${3:-}
    local asset_name=${4:-}
    local asset_id

    if [[ $version != 'latest' ]]; then
        version="tags/${version}"
    fi

    asset_id="$(curl -fsS \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2026-03-10" \
        "https://api.github.com/repos/${repo}/releases/${version}" \
        | jq -r --arg asset_name "${asset_name}" '.assets[]|select(.name==$asset_name)|.id')"
    curl -fsSL \
        -H 'Accept: application/octet-stream' \
        -o "$target" \
        "https://api.github.com/repos/${repo}/releases/assets/${asset_id}"
}

verify_checksum() {
    local filepath="$1"
    local expected_checksum="$2"

    local checksum; checksum="$(checksum_sha256 "$filepath")"
    if [[ "$checksum" != "$expected_checksum" ]]; then
        return 1
    fi
    return 0
}

main "$@"
