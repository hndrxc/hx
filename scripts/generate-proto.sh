#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUF_VERSION="v1.75.0"
PROTOC_GEN_GO_VERSION="v1.36.12"
PROTOC_GEN_CONNECT_GO_VERSION="v2.0.2"

TOOL_BIN="$(mktemp -d)"
trap 'rm -rf "$TOOL_BIN"' EXIT

export GOBIN="$TOOL_BIN"
go install "github.com/bufbuild/buf/cmd/buf@${BUF_VERSION}"
go install "google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}"
go install "connectrpc.com/connect/v2/cmd/protoc-gen-connect-go@${PROTOC_GEN_CONNECT_GO_VERSION}"
export PATH="$TOOL_BIN:$PATH"

"$TOOL_BIN/buf" lint
"$TOOL_BIN/buf" generate
