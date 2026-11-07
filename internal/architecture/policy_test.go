package architecture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// modulePrefix is the canonical Go module path for hx.
const modulePrefix = "github.com/hndrxc/hx"

// normalizePkg trims the module prefix and leading/trailing slashes.
func normalizePkg(p string) string {
	p = strings.TrimPrefix(p, modulePrefix+"/")
	p = strings.TrimPrefix(p, modulePrefix)
	return strings.Trim(p, "/")
}

// matchPkgPrefix returns true if pkg is equal to prefix or is a nested subpackage of prefix,
// comparing by path segments rather than naive string prefixes.
func matchPkgPrefix(pkg, prefix string) bool {
	pkgRel := normalizePkg(pkg)
	prefixRel := normalizePkg(prefix)

	if pkgRel == "" && prefixRel == "" {
		return true
	}
	if pkgRel == "" || prefixRel == "" {
		return false
	}

	return pkgRel == prefixRel || strings.HasPrefix(pkgRel, prefixRel+"/")
}

// isInternal returns true if the package belongs to the hx module.
func isInternal(pkg string) bool {
	if strings.HasPrefix(pkg, modulePrefix+"/") || pkg == modulePrefix {
		return true
	}
	rel := normalizePkg(pkg)
	return strings.HasPrefix(rel, "internal/") || strings.HasPrefix(rel, "cmd/") || strings.HasPrefix(rel, "proto/")
}

// trace records a reachable dependency and the path taken to reach it.
type trace struct {
	pkg  string
	path []string
}

// getReachableInternalDeps performs a breadth-first search to find all reachable
// internal dependencies from start in the given dependency graph.
func getReachableInternalDeps(start string, graph map[string][]string) []trace {
	queue := []trace{{pkg: start, path: []string{start}}}
	visited := map[string]bool{start: true}
	var reachable []trace

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for _, imp := range graph[curr.pkg] {
			if !isInternal(imp) {
				continue
			}
			nextPath := append(append([]string(nil), curr.path...), imp)
			reachable = append(reachable, trace{pkg: imp, path: nextPath})
			if !visited[imp] {
				visited[imp] = true
				queue = append(queue, trace{pkg: imp, path: nextPath})
			}
		}
	}
	return reachable
}

// validate checks a dependency graph against the ADR-0011 architectural rules.
// It returns a list of violation descriptions. An empty slice indicates full compliance.
func validate(graph map[string][]string) []string {
	var violations []string

	// Rule 1: Leaf foundational packages.
	// ADR-0011: leaf packages (internal/domain, internal/secret, internal/sanitize, internal/buildinfo)
	// must not import any other internal package (including other packages in their own subtree).
	leafPackages := []string{
		"internal/buildinfo",
		"internal/domain",
		"internal/secret",
		"internal/sanitize",
	}

	// Rule 3: Client packages and separate client binaries isolation.
	clientTargets := []string{
		"internal/client",
		"internal/cli",
		"internal/tui",
		"internal/desktop",
		"internal/agent",
		"cmd/hx-desktop",
		"cmd/hx-agent",
	}
	forbiddenForClients := []string{
		"internal/hub",
		"internal/egress",
		"internal/collector",
		"internal/integrations",
	}

	// Rule 4: Provider integrations isolation.
	// ADR-0011 explicit allowlist: collector, egress, domain, secret, sanitize only.
	allowedForIntegrations := []string{
		"internal/collector",
		"internal/egress",
		"internal/domain",
		"internal/secret",
		"internal/sanitize",
	}

	for start := range graph {
		deps := getReachableInternalDeps(start, graph)

		// Rule 1: Leaf packages must not import any other internal package.
		for _, leaf := range leafPackages {
			if matchPkgPrefix(start, leaf) {
				for _, dep := range deps {
					if normalizePkg(dep.pkg) != normalizePkg(start) {
						violations = append(violations, fmt.Sprintf(
							"leaf package %s violates policy: forbidden dependency on %s via path: %s",
							start, dep.pkg, strings.Join(dep.path, " -> "),
						))
					}
				}
			}
		}

		// Rule 2: API package may internally depend on internal/domain only.
		// Generated protobuf / Connect code in internal/api may depend on other packages
		// within the internal/api subtree, but only internal/domain is allowed for non-self/external
		// internal imports.
		if matchPkgPrefix(start, "internal/api") {
			for _, dep := range deps {
				if !matchPkgPrefix(dep.pkg, "internal/api") && !matchPkgPrefix(dep.pkg, "internal/domain") {
					violations = append(violations, fmt.Sprintf(
						"api package %s violates policy: forbidden dependency on %s via path: %s",
						start, dep.pkg, strings.Join(dep.path, " -> "),
					))
				}
			}
		}

		// Rule 3: Client packages and separate client binaries must never reach hub, egress, collector, or integrations.
		for _, client := range clientTargets {
			if matchPkgPrefix(start, client) {
				for _, dep := range deps {
					for _, forbidden := range forbiddenForClients {
						if matchPkgPrefix(dep.pkg, forbidden) {
							violations = append(violations, fmt.Sprintf(
								"client package/binary %s violates policy: forbidden transitive dependency on %s via path: %s",
								start, dep.pkg, strings.Join(dep.path, " -> "),
							))
						}
					}
				}
			}
		}

		// Rule 4: Provider integrations may only import collector, egress, domain, secret, sanitize.
		// Cross-provider imports under internal/integrations are rejected.
		if matchPkgPrefix(start, "internal/integrations") {
			for _, dep := range deps {
				if matchPkgPrefix(dep.pkg, "internal/hub") {
					violations = append(violations, fmt.Sprintf(
						"integration package %s violates policy: forbidden dependency on hub %s via path: %s",
						start, dep.pkg, strings.Join(dep.path, " -> "),
					))
					continue
				}
				allowed := false
				for _, okTarget := range allowedForIntegrations {
					if matchPkgPrefix(dep.pkg, okTarget) {
						allowed = true
						break
					}
				}
				if !allowed {
					violations = append(violations, fmt.Sprintf(
						"integration package %s violates policy: unauthorized internal dependency on %s via path: %s",
						start, dep.pkg, strings.Join(dep.path, " -> "),
					))
				}
			}
		}

		// Rule 5: Hub core wiring: Only internal/hub may directly wire integrations.
		for _, imp := range graph[start] {
			if matchPkgPrefix(imp, "internal/integrations") {
				if !matchPkgPrefix(start, "internal/hub") {
					violations = append(violations, fmt.Sprintf(
						"package %s violates wiring policy: only internal/hub may directly import integration package %s",
						start, imp,
					))
				}
			}
		}
	}

	return violations
}

// packageJSON represents package metadata emitted by `go list -json`.
type packageJSON struct {
	Dir        string   `json:"Dir"`
	ImportPath string   `json:"ImportPath"`
	Imports    []string `json:"Imports"`
}

// getModulePath extracts the module path from go.mod in repoRoot, falling back to modulePrefix.
func getModulePath(repoRoot string) string {
	data, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "module" {
				return strings.Trim(fields[1], `"`)
			}
		}
	}
	return modulePrefix
}

// sliceContains checks if item is in slice.
func sliceContains(s []string, item string) bool {
	for _, v := range s {
		if v == item {
			return true
		}
	}
	return false
}

// loadPackageGraph executes `go list -deps -json ./...` in repoRoot and constructs
// the internal package dependency graph, supplemented by scanning cmd and internal
// source directories for all Go files (including build-tagged/ignored files).
func loadPackageGraph(repoRoot string) (map[string][]string, error) {
	cmd := exec.Command("go", "list", "-deps", "-json", "./...")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list failed: %w", err)
	}

	graph := make(map[string][]string)
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p packageJSON
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("failed to decode go list json: %w", err)
		}
		if isInternal(p.ImportPath) {
			graph[p.ImportPath] = append([]string(nil), p.Imports...)
		}
	}

	modPath := getModulePath(repoRoot)

	// Supplement repository-owned production Go imports by scanning cmd and internal source dirs.
	scanDirs := []string{"cmd", "internal"}
	fset := token.NewFileSet()

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

			node, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				return fmt.Errorf("failed to parse %s: %w", path, err)
			}

			if _, exists := graph[pkgPath]; !exists {
				graph[pkgPath] = []string{}
			}

			for _, spec := range node.Imports {
				impVal, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					return fmt.Errorf("failed to unquote import %s in %s: %w", spec.Path.Value, path, err)
				}
				if !sliceContains(graph[pkgPath], impVal) {
					graph[pkgPath] = append(graph[pkgPath], impVal)
				}
			}

			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return graph, nil
}
