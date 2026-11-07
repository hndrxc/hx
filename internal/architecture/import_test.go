package architecture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// findRepoRoot locates the root of the repository by walking up to find go.mod.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repository root containing go.mod")
		}
		dir = parent
	}
}

// TestImportPolicy_LiveRepo verifies that all packages currently in the repository
// adhere strictly to the ADR-0011 architectural rules.
func TestImportPolicy_LiveRepo(t *testing.T) {
	repoRoot := findRepoRoot(t)
	graph, err := loadPackageGraph(repoRoot)
	if err != nil {
		t.Fatalf("failed to load package graph: %v", err)
	}

	violations := validate(graph)
	if len(violations) > 0 {
		for _, v := range violations {
			t.Errorf("architectural violation: %s", v)
		}
	}
}

// TestImportPolicy_PathPrefixMatching verifies that package path matching operates
// strictly on path segments, preventing substring prefix false positives.
func TestImportPolicy_PathPrefixMatching(t *testing.T) {
	tests := []struct {
		pkg      string
		target   string
		expected bool
	}{
		{"github.com/hndrxc/hx/internal/hub", "internal/hub", true},
		{"github.com/hndrxc/hx/internal/hub/vault", "internal/hub", true},
		{"github.com/hndrxc/hx/internal/hub/audit/chain", "internal/hub", true},
		{"internal/hub", "internal/hub", true},
		{"internal/hub/vault", "internal/hub", true},
		// Lookalikes: must NOT match
		{"github.com/hndrxc/hx/internal/hubris", "internal/hub", false},
		{"github.com/hndrxc/hx/internal/hub-agent", "internal/hub", false},
		{"github.com/hndrxc/hx/cmd/hx-agent", "cmd/hx", false},
		{"github.com/hndrxc/hx/cmd/hx-desktop", "cmd/hx", false},
		{"github.com/hndrxc/hx/cmd/hx", "cmd/hx", true},
		{"github.com/hndrxc/hx/internal/cli", "internal/client", false},
		{"github.com/hndrxc/hx/internal/client", "internal/cli", false},
		{"github.com/hndrxc/hx/internal/egress-test", "internal/egress", false},
		{"github.com/hndrxc/hx/internal/collector-fake", "internal/collector", false},
		{"github.com/hndrxc/hx/internal/integrations-mock", "internal/integrations", false},
	}

	for _, tc := range tests {
		got := matchPkgPrefix(tc.pkg, tc.target)
		if got != tc.expected {
			t.Errorf("matchPkgPrefix(%q, %q) = %v, want %v", tc.pkg, tc.target, got, tc.expected)
		}
	}
}

// TestImportPolicy_NegativeCases asserts that the policy engine flags forbidden
// dependency chains across all negative architectural scenarios.
func TestImportPolicy_NegativeCases(t *testing.T) {
	tests := []struct {
		name          string
		graph         map[string][]string
		wantViolation string
	}{
		{
			name: "indirect client to benign helper to hub",
			graph: map[string][]string{
				"github.com/hndrxc/hx/cmd/hx-agent":         {"github.com/hndrxc/hx/internal/agent"},
				"github.com/hndrxc/hx/internal/agent":       {"github.com/hndrxc/hx/internal/util/helper"},
				"github.com/hndrxc/hx/internal/util/helper": {"github.com/hndrxc/hx/internal/hub/vault"},
				"github.com/hndrxc/hx/internal/hub/vault":   {},
			},
			wantViolation: "forbidden transitive dependency on github.com/hndrxc/hx/internal/hub/vault",
		},
		{
			name: "client subtree internal/cli importing hub directly",
			graph: map[string][]string{
				"github.com/hndrxc/hx/internal/cli":       {"github.com/hndrxc/hx/internal/hub"},
				"github.com/hndrxc/hx/internal/hub":       {},
				"github.com/hndrxc/hx/internal/buildinfo": {},
			},
			wantViolation: "client package/binary github.com/hndrxc/hx/internal/cli violates policy",
		},
		{
			name: "client binary cmd/hx-desktop importing egress",
			graph: map[string][]string{
				"github.com/hndrxc/hx/cmd/hx-desktop":  {"github.com/hndrxc/hx/internal/egress"},
				"github.com/hndrxc/hx/internal/egress": {},
			},
			wantViolation: "client package/binary github.com/hndrxc/hx/cmd/hx-desktop violates policy",
		},
		{
			name: "client binary cmd/hx-agent importing collector",
			graph: map[string][]string{
				"github.com/hndrxc/hx/cmd/hx-agent":       {"github.com/hndrxc/hx/internal/collector"},
				"github.com/hndrxc/hx/internal/collector": {},
			},
			wantViolation: "client package/binary github.com/hndrxc/hx/cmd/hx-agent violates policy",
		},
		{
			name: "leaf package internal/buildinfo importing internal/domain",
			graph: map[string][]string{
				"github.com/hndrxc/hx/internal/buildinfo": {"github.com/hndrxc/hx/internal/domain"},
				"github.com/hndrxc/hx/internal/domain":    {},
			},
			wantViolation: "leaf package github.com/hndrxc/hx/internal/buildinfo violates policy",
		},
		{
			name: "leaf package internal/secret importing internal/sanitize",
			graph: map[string][]string{
				"github.com/hndrxc/hx/internal/secret":   {"github.com/hndrxc/hx/internal/sanitize"},
				"github.com/hndrxc/hx/internal/sanitize": {},
			},
			wantViolation: "leaf package github.com/hndrxc/hx/internal/secret violates policy",
		},
		{
			name: "api package importing unauthorized internal/secret",
			graph: map[string][]string{
				"github.com/hndrxc/hx/internal/api":    {"github.com/hndrxc/hx/internal/secret"},
				"github.com/hndrxc/hx/internal/secret": {},
			},
			wantViolation: "api package github.com/hndrxc/hx/internal/api violates policy",
		},
		{
			name: "integration package importing hub",
			graph: map[string][]string{
				"github.com/hndrxc/hx/internal/integrations/aws": {"github.com/hndrxc/hx/internal/hub/vault"},
				"github.com/hndrxc/hx/internal/hub/vault":        {},
			},
			wantViolation: "integration package github.com/hndrxc/hx/internal/integrations/aws violates policy: forbidden dependency on hub",
		},
		{
			name: "integration package importing unauthorized internal/cli",
			graph: map[string][]string{
				"github.com/hndrxc/hx/internal/integrations/aws": {"github.com/hndrxc/hx/internal/cli"},
				"github.com/hndrxc/hx/internal/cli":              {},
			},
			wantViolation: "integration package github.com/hndrxc/hx/internal/integrations/aws violates policy: unauthorized internal dependency",
		},
		{
			name: "unauthorized wiring of integrations by non-hub package",
			graph: map[string][]string{
				"github.com/hndrxc/hx/internal/tui":                 {"github.com/hndrxc/hx/internal/integrations/github"},
				"github.com/hndrxc/hx/internal/integrations/github": {},
			},
			wantViolation: "violates wiring policy: only internal/hub may directly import integration package",
		},
		{
			name: "leaf package internal/buildinfo importing subpackage in own subtree",
			graph: map[string][]string{
				"github.com/hndrxc/hx/internal/buildinfo":         {"github.com/hndrxc/hx/internal/buildinfo/version"},
				"github.com/hndrxc/hx/internal/buildinfo/version": {},
			},
			wantViolation: "leaf package github.com/hndrxc/hx/internal/buildinfo violates policy: forbidden dependency on github.com/hndrxc/hx/internal/buildinfo/version",
		},
		{
			name: "provider integration importing another provider integration",
			graph: map[string][]string{
				"github.com/hndrxc/hx/internal/integrations/aws":    {"github.com/hndrxc/hx/internal/integrations/github"},
				"github.com/hndrxc/hx/internal/integrations/github": {},
			},
			wantViolation: "integration package github.com/hndrxc/hx/internal/integrations/aws violates policy: unauthorized internal dependency on github.com/hndrxc/hx/internal/integrations/github",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			violations := validate(tc.graph)
			if len(violations) == 0 {
				t.Fatalf("expected violation matching %q, got 0 violations", tc.wantViolation)
			}
			matched := false
			for _, v := range violations {
				if strings.Contains(v, tc.wantViolation) {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("expected violation containing %q, got:\n%s", tc.wantViolation, strings.Join(violations, "\n"))
			}
		})
	}
}

// TestImportPolicy_LookalikesNotMisclassified verifies that prefix lookalikes
// (e.g., internal/hubris, internal/egress-test) are not falsely rejected.
func TestImportPolicy_LookalikesNotMisclassified(t *testing.T) {
	graph := map[string][]string{
		"github.com/hndrxc/hx/cmd/hx-agent": {
			"github.com/hndrxc/hx/internal/cli",
		},
		"github.com/hndrxc/hx/internal/cli": {
			"github.com/hndrxc/hx/internal/hubris",
			"github.com/hndrxc/hx/internal/egress-test",
			"github.com/hndrxc/hx/internal/collector-fake",
			"github.com/hndrxc/hx/internal/integrations-mock",
		},
		"github.com/hndrxc/hx/internal/hubris":            {},
		"github.com/hndrxc/hx/internal/egress-test":       {},
		"github.com/hndrxc/hx/internal/collector-fake":    {},
		"github.com/hndrxc/hx/internal/integrations-mock": {},
	}

	violations := validate(graph)
	if len(violations) > 0 {
		t.Fatalf("lookalike packages should not produce violations, got: %v", violations)
	}
}

// TestImportPolicy_ValidComposition asserts that the intended cmd/hx composition
// (unifying hub and client front-end without leaking hub into internal/cli) passes validation.
func TestImportPolicy_ValidComposition(t *testing.T) {
	graph := map[string][]string{
		"github.com/hndrxc/hx/cmd/hx": {
			"github.com/hndrxc/hx/internal/cli",
			"github.com/hndrxc/hx/internal/hub",
			"github.com/hndrxc/hx/internal/buildinfo",
		},
		"github.com/hndrxc/hx/internal/cli": {
			"github.com/hndrxc/hx/internal/buildinfo",
			"github.com/hndrxc/hx/internal/client",
		},
		"github.com/hndrxc/hx/internal/client": {
			"github.com/hndrxc/hx/internal/domain",
		},
		"github.com/hndrxc/hx/internal/hub": {
			"github.com/hndrxc/hx/internal/domain",
			"github.com/hndrxc/hx/internal/secret",
			"github.com/hndrxc/hx/internal/integrations/github",
		},
		"github.com/hndrxc/hx/internal/integrations/github": {
			"github.com/hndrxc/hx/internal/collector",
			"github.com/hndrxc/hx/internal/domain",
			"github.com/hndrxc/hx/internal/secret",
		},
		"github.com/hndrxc/hx/internal/domain":    {},
		"github.com/hndrxc/hx/internal/secret":    {},
		"github.com/hndrxc/hx/internal/collector": {},
		"github.com/hndrxc/hx/internal/buildinfo": {},
	}

	violations := validate(graph)
	if len(violations) > 0 {
		t.Fatalf("valid cmd/hx composition should pass with 0 violations, got: %v", violations)
	}
}

// TestImportPolicy_TaggedOnlyDirectoryDetection verifies that LoadPackageGraph supplements
// the go list package graph by inspecting ignored/build-tagged directories, ensuring that
// forbidden dependencies in inactive targets (such as desktop-tagged client packages) are caught.
func TestImportPolicy_TaggedOnlyDirectoryDetection(t *testing.T) {
	tmpDir := t.TempDir()

	goMod := "module github.com/hndrxc/hx\n\ngo 1.27.3\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatalf("failed to write go.mod: %v", err)
	}

	cmdDir := filepath.Join(tmpDir, "cmd", "hx")
	if err := os.MkdirAll(cmdDir, 0755); err != nil {
		t.Fatalf("failed to create cmd dir: %v", err)
	}
	cmdSrc := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(cmdDir, "main.go"), []byte(cmdSrc), 0644); err != nil {
		t.Fatalf("failed to write main.go: %v", err)
	}

	clientDir := filepath.Join(tmpDir, "internal", "cli", "desktop")
	if err := os.MkdirAll(clientDir, 0755); err != nil {
		t.Fatalf("failed to create client dir: %v", err)
	}
	clientSrc := "//go:build desktop\n\npackage desktop\n\nimport _ \"github.com/hndrxc/hx/internal/hub/vault\"\n"
	if err := os.WriteFile(filepath.Join(clientDir, "desktop.go"), []byte(clientSrc), 0644); err != nil {
		t.Fatalf("failed to write desktop.go: %v", err)
	}

	graph, err := loadPackageGraph(tmpDir)
	if err != nil {
		t.Fatalf("loadPackageGraph failed: %v", err)
	}

	violations := validate(graph)
	if len(violations) == 0 {
		t.Fatal("expected policy violation for tagged-only client importing internal/hub/vault, got 0 violations")
	}

	expectedSubstring := "forbidden transitive dependency on github.com/hndrxc/hx/internal/hub/vault"
	matched := false
	for _, v := range violations {
		if strings.Contains(v, expectedSubstring) && strings.Contains(v, "internal/cli/desktop") {
			matched = true
			break
		}
	}
	if !matched {
		t.Errorf("expected violation mentioning internal/cli/desktop and %q, got:\n%s",
			expectedSubstring, strings.Join(violations, "\n"))
	}
}

// TestImportPolicy_ParseErrorHandling verifies that malformed ignored or build-tagged source
// files fail loadPackageGraph with a descriptive error rather than silently passing.
func TestImportPolicy_ParseErrorHandling(t *testing.T) {
	tmpDir := t.TempDir()

	goMod := "module github.com/hndrxc/hx\n\ngo 1.27.3\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatalf("failed to write go.mod: %v", err)
	}

	cmdDir := filepath.Join(tmpDir, "cmd", "hx")
	if err := os.MkdirAll(cmdDir, 0755); err != nil {
		t.Fatalf("failed to create cmd dir: %v", err)
	}
	cmdSrc := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(cmdDir, "main.go"), []byte(cmdSrc), 0644); err != nil {
		t.Fatalf("failed to write main.go: %v", err)
	}

	brokenDir := filepath.Join(tmpDir, "internal", "cli", "broken")
	if err := os.MkdirAll(brokenDir, 0755); err != nil {
		t.Fatalf("failed to create broken dir: %v", err)
	}
	brokenSrc := "//go:build desktop\n\npackage broken\n\nimport (\n"
	if err := os.WriteFile(filepath.Join(brokenDir, "broken.go"), []byte(brokenSrc), 0644); err != nil {
		t.Fatalf("failed to write broken.go: %v", err)
	}

	_, err := loadPackageGraph(tmpDir)
	if err == nil {
		t.Fatal("expected loadPackageGraph to fail on malformed tagged source file, got nil error")
	}
}
