// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

// Command licenses enforces SecretMesh's dependency licence policy and keeps
// docs/legal/THIRD_PARTY_LICENSES.md in step with the dependency tree.
//
//	go run ./scripts/licenses check    fail on any licence outside docs/legal/license-policy.json
//	go run ./scripts/licenses update   rewrite the generated part of THIRD_PARTY_LICENSES.md
//	go run ./scripts/licenses verify   fail if that generated part is out of date
//	go run ./scripts/licenses headers-check   fail if a source file lacks the SPDX licence header
//	go run ./scripts/licenses headers-apply   add the header, or update it when the licence ID changes
//
// It uses go-licenses for Go modules and license-checker for npm packages, both
// pinned below. It never changes dependencies and sends nothing anywhere.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	goLicenses     = "github.com/google/go-licenses/v2@v2.0.1"
	npmChecker     = "license-checker-rseidelsohn@4.4.2"
	policyPath     = "docs/legal/license-policy.json"
	docPath        = "docs/legal/THIRD_PARTY_LICENSES.md"
	beginMarker    = "<!-- BEGIN GENERATED: scripts/licenses -->"
	endMarker      = "<!-- END GENERATED -->"
	mainPackage    = "./apps/api"
	webDir         = "apps/web"
	ownModulePath  = "github.com/secretmesh/secretmesh"
	unknownLicense = "Unknown"
)

type policy struct {
	Allowed        []string `json:"allowed"`
	Denied         []string `json:"denied"`
	IgnorePackages []string `json:"ignorePackages"`
	Exceptions     []struct {
		Ecosystem string `json:"ecosystem"`
		Package   string `json:"package"`
		License   string `json:"license"`
		Reason    string `json:"reason"`
	} `json:"exceptions"`
}

type dep struct{ Name, License string }

func main() {
	if len(os.Args) != 2 {
		fail("usage: licenses check|update|verify|headers-check|headers-apply")
	}
	if strings.HasPrefix(os.Args[1], "headers-") {
		headers(os.Args[1] == "headers-apply")
		return
	}
	pol := loadPolicy()
	goDeps, err := goDependencies(pol)
	must(err)
	npmProd, err := npmDependencies(pol, true)
	must(err)
	switch os.Args[1] {
	case "check":
		npmAll, err := npmDependencies(pol, false)
		must(err)
		var bad []string
		bad = append(bad, violations(pol, "go", goDeps)...)
		bad = append(bad, violations(pol, "npm", npmAll)...)
		if len(bad) > 0 {
			fail("licence policy violations (see " + policyPath + "):\n  " + strings.Join(bad, "\n  "))
		}
		fmt.Printf("ok: %d Go modules and %d npm packages (%d in production) follow the licence policy\n", len(goDeps), len(npmAll), len(npmProd))
	case "update", "verify":
		want := replaceGenerated(readDoc(), render(goDeps, npmProd))
		if os.Args[1] == "update" {
			must(os.WriteFile(docPath, []byte(want), 0o644)) // #nosec G306 -- generated licence notices are public.
			fmt.Println("updated", docPath)
			return
		}
		if readDoc() != want {
			fail(docPath + " is out of date; run `make license-report` and commit the result")
		}
		fmt.Println("ok:", docPath, "is up to date")
	default:
		fail("unknown command " + os.Args[1])
	}
}

func loadPolicy() policy {
	b, err := os.ReadFile(policyPath)
	must(err)
	var p policy
	must(json.Unmarshal(b, &p))
	return p
}

// goDependencies lists the modules compiled into the API binary with the
// licence go-licenses detects. GOOS is pinned so the result is the same on
// every machine.
func goDependencies(pol policy) ([]dep, error) {
	env := append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	list, err := run("", env, "go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}} {{with .Module}}{{.Path}}{{end}}{{end}}", mainPackage)
	if err != nil {
		return nil, err
	}
	moduleOf := map[string]string{}
	modules := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(list), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 {
			moduleOf[f[0]] = f[1]
			modules[f[1]] = true
		}
	}
	tpl, err := os.CreateTemp("", "licenses-*.tpl")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tpl.Name()) }()
	_, _ = tpl.WriteString("{{range .}}{{.Name}}|{{.LicenseName}}\n{{end}}")
	_ = tpl.Close()
	bin, cleanup, err := installGoLicenses()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	out, err := run("", env, bin, "report", mainPackage+"/...", "--template", tpl.Name())
	if err != nil {
		return nil, err
	}
	perModule := map[string]map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		pkg, lic, ok := strings.Cut(l, "|")
		if !ok {
			continue
		}
		if lic == "" {
			lic = unknownLicense
		}
		mod := moduleOf[pkg]
		if mod == "" {
			mod = longestPrefix(pkg, modules)
		}
		if mod == "" {
			mod = pkg
		}
		if perModule[mod] == nil {
			perModule[mod] = map[string]bool{}
		}
		perModule[mod][lic] = true
	}
	var deps []dep
	for mod, lics := range perModule {
		if ignored(pol, mod) {
			continue
		}
		deps = append(deps, dep{mod, join(lics)})
	}
	sortDeps(deps)
	return deps, nil
}

// installGoLicenses builds the pinned go-licenses with the host's normal
// settings: it must run on this machine even though it analyses linux/amd64.
func installGoLicenses() (bin string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "go-licenses-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	if _, err := run("", append(os.Environ(), "GOBIN="+dir), "go", "install", goLicenses); err != nil {
		cleanup()
		return "", nil, err
	}
	return path.Join(dir, "go-licenses"), cleanup, nil
}

var platformPackage = regexp.MustCompile(`^(@img/sharp(?:-libvips)?|@next/swc)-(?:darwin|linux|linuxmusl|win32|freebsd|android|openharmony|wasm32)(?:-[a-z0-9]+)*$`)

// npmDependencies lists packages of the web app. Platform-specific binary
// packages are folded into one family entry so the list does not depend on the
// machine that installed them.
func npmDependencies(pol policy, production bool) ([]dep, error) {
	args := []string{"--yes", npmChecker, "--json"}
	if production {
		args = append(args, "--production")
	}
	out, err := run(webDir, nil, "npx", args...)
	if err != nil {
		return nil, err
	}
	var raw map[string]struct {
		Licenses any `json:"licenses"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parse license-checker output: %w", err)
	}
	seen := map[string]map[string]bool{}
	for key, v := range raw {
		name := key[:strings.LastIndex(key, "@")]
		if m := platformPackage.FindStringSubmatch(name); m != nil {
			name = m[1] + "-*"
		}
		if ignored(pol, name) {
			continue
		}
		if seen[name] == nil {
			seen[name] = map[string]bool{}
		}
		switch l := v.Licenses.(type) {
		case string:
			seen[name][strings.Trim(l, "()*")] = true
		case []any:
			for _, x := range l {
				seen[name][fmt.Sprint(x)] = true
			}
		}
	}
	var deps []dep
	for name, lics := range seen {
		deps = append(deps, dep{name, join(lics)})
	}
	sortDeps(deps)
	return deps, nil
}

// violations reports dependencies whose licence is not allowed. A dependency
// with several licences ("MIT OR Apache-2.0") passes if every alternative is
// allowed or covered by an exception; "AND" requires all of them.
func violations(pol policy, ecosystem string, deps []dep) []string {
	allowed := map[string]bool{}
	for _, a := range pol.Allowed {
		allowed[a] = true
	}
	var bad []string
	for _, d := range deps {
		for _, lic := range splitLicenses(d.License) {
			if allowed[lic] || excepted(pol, ecosystem, d.Name, lic) {
				continue
			}
			bad = append(bad, fmt.Sprintf("%s %s: %s is not allowed", ecosystem, d.Name, lic))
		}
	}
	return bad
}

func excepted(pol policy, ecosystem, name, lic string) bool {
	for _, e := range pol.Exceptions {
		if e.Ecosystem == ecosystem && e.License == lic {
			if ok, _ := path.Match(e.Package, name); ok {
				return true
			}
		}
	}
	return false
}

func ignored(pol policy, name string) bool {
	for _, p := range pol.IgnorePackages {
		if name == p || strings.HasPrefix(name, p+"/") && p == ownModulePath {
			return true
		}
	}
	return false
}

func splitLicenses(s string) []string {
	s = strings.NewReplacer("(", " ", ")", " ", " OR ", ",", " AND ", ",", " or ", ",", " and ", ",").Replace(s)
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(strings.TrimSuffix(p, "*")); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func render(goDeps, npmProd []dep) string {
	var b strings.Builder
	b.WriteString(beginMarker + "\n\n")
	b.WriteString("_Generated by `make license-report` from the dependency tree; do not edit by hand. Versions are omitted on purpose so routine dependency updates do not change this file; any added or removed dependency, or a changed licence, does._\n\n")
	table(&b, fmt.Sprintf("Go modules compiled into the API binary (%d)", len(goDeps)), goDeps)
	table(&b, fmt.Sprintf("npm packages shipped with the web console (%d)", len(npmProd)), npmProd)
	b.WriteString(endMarker)
	return b.String()
}

func table(b *strings.Builder, title string, deps []dep) {
	b.WriteString("### " + title + "\n\n| Package | Licence |\n|---------|---------|\n")
	for _, d := range deps {
		fmt.Fprintf(b, "| `%s` | %s |\n", d.Name, d.License)
	}
	b.WriteString("\n")
}

func replaceGenerated(doc, generated string) string {
	i, j := strings.Index(doc, beginMarker), strings.Index(doc, endMarker)
	if i < 0 || j < i {
		fail(docPath + " must contain the markers " + beginMarker + " ... " + endMarker)
	}
	return doc[:i] + generated + doc[j+len(endMarker):]
}

func readDoc() string {
	b, err := os.ReadFile(docPath)
	must(err)
	return string(b)
}

func run(dir string, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(context.Background(), name, args...) // #nosec G204 -- callers select pinned local tooling, never external input.
	cmd.Dir, cmd.Env = dir, env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, lastLines(stderr.String(), 12))
	}
	return stdout.String(), nil
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

func longestPrefix(pkg string, modules map[string]bool) string {
	best := ""
	for m := range modules {
		if (pkg == m || strings.HasPrefix(pkg, m+"/")) && len(m) > len(best) {
			best = m
		}
	}
	return best
}

func join(set map[string]bool) string {
	var l []string
	for k := range set {
		l = append(l, k)
	}
	sort.Strings(l)
	return strings.Join(l, ", ")
}

func sortDeps(d []dep) { sort.Slice(d, func(i, j int) bool { return d[i].Name < d[j].Name }) }

func must(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "error:", msg)
	os.Exit(1)
}
