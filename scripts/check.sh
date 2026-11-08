#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

usage() {
    echo "Usage: $0 {formatting|build|test|generated|all}" >&2
    exit 1
}

check_formatting() {
    echo "==> Running formatting check (gofmt)..."
    local files=()
    # wait propagates process-substitution producer failure under set -e
    mapfile -d '' -t files < <(git ls-files -z '*.go')
    wait "$!"

    if [[ ${#files[@]} -eq 0 ]]; then
        echo "No tracked Go files found."
        return 0
    fi

    local unformatted_output
    unformatted_output=$(gofmt -l -e "${files[@]}")

    if [[ -n "$unformatted_output" ]]; then
        echo "Error: Unformatted Go source files found:" >&2
        while IFS= read -r file; do
            [[ -n "$file" ]] && echo " - $file" >&2
        done <<< "$unformatted_output"
        echo "" >&2
        echo "--- Formatting diff ---" >&2
        gofmt -d -e "${files[@]}" >&2
        return 1
    fi
    echo "Formatting check passed: all tracked Go files are properly formatted."
    return 0
}

check_build() {
    (
        echo "==> Running build check (cross-compilation targets)..."
        build_dir=$(mktemp -d)
        trap 'rm -rf "$build_dir"' EXIT INT TERM

        echo "Building linux/amd64 targets (hx, hx-agent, hx-desktop)..."
        CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$build_dir/hx-linux-amd64" ./cmd/hx
        CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$build_dir/hx-agent-linux-amd64" ./cmd/hx-agent
        CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$build_dir/hx-desktop-linux-amd64" ./cmd/hx-desktop

        echo "Building windows/amd64 targets (hx, hx-agent, hx-desktop)..."
        CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o "$build_dir/hx-windows-amd64.exe" ./cmd/hx
        CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o "$build_dir/hx-agent-windows-amd64.exe" ./cmd/hx-agent
        CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o "$build_dir/hx-desktop-windows-amd64.exe" ./cmd/hx-desktop

        echo "Building linux/arm64 targets (hx-agent)..."
        CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$build_dir/hx-agent-linux-arm64" ./cmd/hx-agent

        echo "Build check passed: all 7 cross-platform binary targets compiled successfully."
    )
}

check_test() {
    echo "==> Running test check (CGO_ENABLED=0 go test ./...)..."
    CGO_ENABLED=0 go test ./...
    echo "Test check passed: all tests succeeded."
    return 0
}

check_generated() {
    echo "==> Running generated files and module verification check..."

    echo "Verifying go.mod tidiness (go mod tidy -diff)..."
    go mod tidy -diff

    echo "Verifying module checksums (go mod verify)..."
    go mod verify

    echo "Executing code generation (go generate ./...)..."
    go generate ./...

    local has_errors=0

    # Check for working tree modifications against the git index
    if ! git diff --exit-code; then
        echo "Error: Unstaged modifications detected after running generation checks." >&2
        has_errors=1
    fi

    # Check for newly created untracked output (excluding ignored files)
    local untracked=()
    mapfile -d '' -t untracked < <(git ls-files -z --others --exclude-standard)
    wait "$!"
    if [[ ${#untracked[@]} -gt 0 ]]; then
        echo "Error: Untracked files detected after running generation checks:" >&2
        printf ' - %s\n' "${untracked[@]}" >&2
        has_errors=1
    fi

    if [[ $has_errors -ne 0 ]]; then
        return 1
    fi

    echo "Generated check passed: module graph verified and working tree clean against index."
    return 0
}

check_all() {
    check_formatting
    check_build
    check_test
    check_generated
    echo "All CI checks passed successfully."
}

if [[ $# -ne 1 ]]; then
    usage
fi

case "$1" in
    formatting)
        check_formatting
        ;;
    build)
        check_build
        ;;
    test)
        check_test
        ;;
    generated)
        check_generated
        ;;
    all)
        check_all
        ;;
    *)
        usage
        ;;
esac
