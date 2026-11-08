package architecture

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const secretPkgPath = "github.com/hndrxc/hx/internal/secret"

// findSecretConstructorCalls checks if the file imports github.com/hndrxc/hx/internal/secret
// and inspects whether it calls FromBytes. Only internal/secret and internal/hub/vault
// are permitted to call FromBytes. Dot imports of internal/secret are reported as violations,
// while blank imports are ignored.
func findSecretConstructorCalls(pkgPath string, file *ast.File) []string {
	var violations []string

	// Check imports of internal/secret
	secretImportNames := make(map[string]bool)
	hasSecretImport := false

	for _, imp := range file.Imports {
		pathVal, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if pathVal != secretPkgPath {
			continue
		}

		hasSecretImport = true
		if imp.Name == nil {
			// Default import name "secret"
			secretImportNames["secret"] = true
		} else if imp.Name.Name == "." {
			violations = append(violations, fmt.Sprintf("package %s dot-imports internal/secret", pkgPath))
		} else if imp.Name.Name == "_" {
			// Blank import ignored
			continue
		} else {
			// Explicit alias
			secretImportNames[imp.Name.Name] = true
		}
	}

	if !hasSecretImport || len(secretImportNames) == 0 {
		return violations
	}

	// Allowed packages: internal/secret and internal/hub/vault
	if matchPkgPrefix(pkgPath, "internal/secret") || matchPkgPrefix(pkgPath, "internal/hub/vault") {
		return violations
	}

	// Inspect AST for selector expressions referencing FromBytes on any matched import identifier
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		if sel.Sel == nil || sel.Sel.Name != "FromBytes" {
			return true
		}

		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		if secretImportNames[ident.Name] {
			violations = append(violations, fmt.Sprintf(
				"package %s violates secret ingestion policy: only internal/hub/vault may construct secret values (FromBytes)",
				pkgPath,
			))
		}
		return true
	})

	return violations
}

// loadSecretConstructorViolations walks cmd and internal, parsing every non-_test.go .go file
// (including build-tagged ones) and returns all secret ingestion violations.
func loadSecretConstructorViolations(repoRoot string) ([]string, error) {
	modPath := getModulePath(repoRoot)
	scanDirs := []string{"cmd", "internal"}
	fset := token.NewFileSet()

	var violations []string

	for _, scanDir := range scanDirs {
		dirRoot := filepath.Join(repoRoot, scanDir)
		if _, err := os.Stat(dirRoot); os.IsNotExist(err) {
			continue
		}

		err := filepath.WalkDir(dirRoot, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				if d.Name() == "vendor" || d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}

			name := d.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}

			relDir, err := filepath.Rel(repoRoot, filepath.Dir(path))
			if err != nil {
				return fmt.Errorf("failed to get relative path for %s: %w", path, err)
			}
			slashRel := filepath.ToSlash(relDir)
			pkgPath := modPath + "/" + slashRel

			node, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return fmt.Errorf("failed to parse %s: %w", path, err)
			}

			fileViolations := findSecretConstructorCalls(pkgPath, node)
			violations = append(violations, fileViolations...)

			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return violations, nil
}

func TestSecretIngestion_LiveRepo(t *testing.T) {
	repoRoot := findRepoRoot(t)
	violations, err := loadSecretConstructorViolations(repoRoot)
	if err != nil {
		t.Fatalf("failed to load secret constructor violations: %v", err)
	}

	if len(violations) > 0 {
		t.Errorf("unexpected secret constructor violations in live repo:\n%s", strings.Join(violations, "\n"))
	}
}

func TestSecretIngestion_Cases(t *testing.T) {
	tests := []struct {
		name               string
		pkgPath            string
		src                string
		expectedViolations []string
	}{
		{
			name:    "internal/integrations/github calling secret.FromBytes",
			pkgPath: "github.com/hndrxc/hx/internal/integrations/github",
			src: `package github
import "github.com/hndrxc/hx/internal/secret"
func Ingest(b []byte) {
	_, _ = secret.FromBytes(b)
}
`,
			expectedViolations: []string{
				"package github.com/hndrxc/hx/internal/integrations/github violates secret ingestion policy: only internal/hub/vault may construct secret values (FromBytes)",
			},
		},
		{
			name:    "aliased import calling s.FromBytes in internal/hub/rpc",
			pkgPath: "github.com/hndrxc/hx/internal/hub/rpc",
			src: `package rpc
import s "github.com/hndrxc/hx/internal/secret"
func Ingest(b []byte) {
	_, _ = s.FromBytes(b)
}
`,
			expectedViolations: []string{
				"package github.com/hndrxc/hx/internal/hub/rpc violates secret ingestion policy: only internal/hub/vault may construct secret values (FromBytes)",
			},
		},
		{
			name:    "dot import in cmd/hx",
			pkgPath: "github.com/hndrxc/hx/cmd/hx",
			src: `package main
import . "github.com/hndrxc/hx/internal/secret"
func run() {}
`,
			expectedViolations: []string{
				"package github.com/hndrxc/hx/cmd/hx dot-imports internal/secret",
			},
		},
		{
			name:    "allowed internal/hub/vault",
			pkgPath: "github.com/hndrxc/hx/internal/hub/vault",
			src: `package vault
import "github.com/hndrxc/hx/internal/secret"
func Create(b []byte) (*secret.Value, error) {
	return secret.FromBytes(b)
}
`,
			expectedViolations: nil,
		},
		{
			name:    "allowed internal/secret",
			pkgPath: "github.com/hndrxc/hx/internal/secret",
			src: `package secret
func FromBytes(b []byte) (*Value, error) {
	return nil, nil
}
`,
			expectedViolations: nil,
		},
		{
			name:    "allowed package using only secret.NewHandle",
			pkgPath: "github.com/hndrxc/hx/internal/collector",
			src: `package collector
import "github.com/hndrxc/hx/internal/secret"
func Init() {
	_ = secret.NewHandle
}
`,
			expectedViolations: nil,
		},
		{
			name:    "blank import is ignored",
			pkgPath: "github.com/hndrxc/hx/internal/collector",
			src: `package collector
import _ "github.com/hndrxc/hx/internal/secret"
`,
			expectedViolations: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "x.go", tc.src, 0)
			if err != nil {
				t.Fatalf("failed to parse test source: %v", err)
			}

			violations := findSecretConstructorCalls(tc.pkgPath, file)
			if len(violations) != len(tc.expectedViolations) {
				t.Fatalf("expected %d violations, got %d: %v", len(tc.expectedViolations), len(violations), violations)
			}

			for i, expected := range tc.expectedViolations {
				if violations[i] != expected {
					t.Errorf("violation[%d] = %q, want %q", i, violations[i], expected)
				}
			}
		})
	}
}

func TestSecretIngestion_TaggedFileDetected(t *testing.T) {
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

	cliDir := filepath.Join(tmpDir, "internal", "cli", "x")
	if err := os.MkdirAll(cliDir, 0755); err != nil {
		t.Fatalf("failed to create cli dir: %v", err)
	}
	taggedSrc := `//go:build desktop

package x

import "github.com/hndrxc/hx/internal/secret"

func Ingest(b []byte) {
	_, _ = secret.FromBytes(b)
}
`
	if err := os.WriteFile(filepath.Join(cliDir, "tagged.go"), []byte(taggedSrc), 0644); err != nil {
		t.Fatalf("failed to write tagged.go: %v", err)
	}

	violations, err := loadSecretConstructorViolations(tmpDir)
	if err != nil {
		t.Fatalf("loadSecretConstructorViolations failed: %v", err)
	}

	if len(violations) != 1 {
		t.Fatalf("expected 1 violation for tagged desktop file, got %d: %v", len(violations), violations)
	}

	expectedSubstring := "package github.com/hndrxc/hx/internal/cli/x violates secret ingestion policy: only internal/hub/vault may construct secret values (FromBytes)"
	if violations[0] != expectedSubstring {
		t.Errorf("expected violation %q, got %q", expectedSubstring, violations[0])
	}
}
