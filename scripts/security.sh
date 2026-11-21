#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Reviewed tool versions.
GOVULNCHECK_VERSION="v1.9.0"
GOSEC_VERSION="v2.30.0"
STATICCHECK_VERSION="v0.8.2"

# Security-patched toolchain for scans; application go.mod is not modified.
export GOTOOLCHAIN="go1.27.4"

# Reviewed #20 gosec suppression (never disables G304 globally).
SUPPRESS_ID="F04-001"
SUPPRESS_RULE="G304"
SUPPRESS_FILE="cmd/hx/audit.go"
SUPPRESS_CODE="os.Open(path)"
SUPPRESS_EXPIRES="2027-02-20"

FUZZ_TARGETS=(
    "./cmd/hx FuzzParseCheckpoint"
    "./internal/hub/audit FuzzVerifyAnchoredFrame"
    "./internal/sanitize FuzzLogProperties"
    "./internal/sanitize FuzzLabelProperties"
    "./internal/secret FuzzRedactionIndependence"
)

usage() {
    echo "Usage: $0 {install|go|fuzz-smoke|fuzz-long}" >&2
    exit 1
}

tool_path() {
    local bin
    bin="$(go env GOBIN)"
    if [[ -z "$bin" ]]; then
        bin="$(go env GOPATH)/bin"
    fi
    export PATH="$bin:$PATH"
}

install_tools() {
    echo "==> Installing reviewed security tools..."
    go install "honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}"
    go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"
    go install "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}"
}

run_gosec() (
    echo "==> Running gosec (inline #nosec ignored)..."
    command -v jq >/dev/null || { echo "Error: jq is required for gosec result checks" >&2; return 1; }

    local out rc=0
    out="$(mktemp)"
    trap 'rm -f -- "$out"' EXIT

    gosec -nosec=true -exclude-dir='(^|/)security/testdata(/|$)' -fmt=json -out "$out" ./... || rc=$?
    if [[ $rc -ne 0 && $rc -ne 1 ]]; then
        echo "Error: gosec failed with exit code $rc (scanner error)" >&2
        return 1
    fi

    if ! jq -e '(.Issues | type == "array") and (.Stats.files > 0)' "$out" >/dev/null; then
        echo "Error: gosec output is invalid or scanned no files" >&2
        return 1
    fi
    if ! jq -e '((."Golang errors" // {}) | length == 0) and ((."Gosec errors" // {}) | length == 0)' "$out" >/dev/null; then
        echo "Error: gosec reported scanner errors:" >&2
        jq '{"Golang errors": ."Golang errors", "Gosec errors": ."Gosec errors"}' "$out" >&2
        return 1
    fi

    local total
    total="$(jq '.Issues | length' "$out")"
    if [[ $rc -eq 1 && "$total" -eq 0 ]]; then
        echo "Error: gosec exited 1 without issues (scanner failure)" >&2
        return 1
    fi
    if [[ $rc -eq 0 && "$total" -ne 0 ]]; then
        echo "Error: gosec exited 0 with issues" >&2
        return 1
    fi

    local today allow_file
    today="$(date -u +%F)"
    allow_file="$REPO_ROOT/$SUPPRESS_FILE"
    if [[ ! "$today" < "$SUPPRESS_EXPIRES" ]]; then
        echo "Warning: suppression $SUPPRESS_ID expired on $SUPPRESS_EXPIRES; not applied" >&2
        allow_file=""
    fi

    local remaining
    remaining="$(jq -c --arg rule "$SUPPRESS_RULE" --arg file "$allow_file" --arg code "$SUPPRESS_CODE" '
        [.Issues[] | .line as $line | select(
            ($file != "" and .rule_id == $rule and .file == $file
             and (.code | split("\n") | any(startswith($line + ": ") and contains($code)))) | not
        )]' "$out")"

    local suppressed=$((total - $(jq 'length' <<<"$remaining")))
    if [[ $suppressed -gt 1 ]]; then
        echo "Error: suppression $SUPPRESS_ID matched more than one finding" >&2
        return 1
    elif [[ $suppressed -eq 1 ]]; then
        echo "Note: $suppressed finding(s) suppressed by $SUPPRESS_ID ($SUPPRESS_RULE in $SUPPRESS_FILE, expires $SUPPRESS_EXPIRES)"
    fi

    if [[ "$(jq 'length' <<<"$remaining")" -ne 0 ]]; then
        echo "Error: gosec findings:" >&2
        jq -r '.[] | "\(.file):\(.line): \(.rule_id) \(.details)"' <<<"$remaining" >&2
        return 1
    fi
)

run_go() {
    tool_path
    echo "==> Using $(go version)"
    echo "==> Running staticcheck..."
    staticcheck ./...
    echo "==> Running govulncheck..."
    govulncheck ./...
    run_gosec
}

run_fuzz() {
    local mode="$1" fuzztime
    case "$mode" in
        smoke) fuzztime="100x" ;;
        long) fuzztime="60s" ;;
        *) usage ;;
    esac

    local entry pkg name listed
    for entry in "${FUZZ_TARGETS[@]}"; do
        pkg="${entry%% *}"
        name="${entry##* }"

        listed="$(CGO_ENABLED=0 go test -list "^${name}\$" "$pkg")"
        if ! grep -Fxq "$name" <<<"$listed"; then
            echo "Error: fuzz target $name not found in $pkg" >&2
            return 1
        fi

        echo "==> Fuzzing $pkg $name ($fuzztime)..."
        CGO_ENABLED=0 go test -run '^$' -fuzz "^${name}\$" -fuzztime "$fuzztime" -parallel 2 "$pkg"
    done
}

case "${1:-}" in
    install) install_tools ;;
    go) run_go ;;
    fuzz-smoke) run_fuzz smoke ;;
    fuzz-long) run_fuzz long ;;
    *) usage ;;
esac
