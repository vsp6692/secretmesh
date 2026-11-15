// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// spdxID names the licence of SecretMesh's own source files. It carries the
// DRAFT marker until the owner adopts the licence; `headers-apply` then
// rewrites every header to the final identifier.
const spdxID = "LicenseRef-SecretMesh-SAL-1.0-DRAFT"

const spdxTag = "SPDX-License-Identifier:"

// commentPrefix returns the line-comment marker for a file, or "" for files
// that carry no header (data, docs, generated and third-party material).
func commentPrefix(file string) string {
	base := filepath.Base(file)
	switch strings.ToLower(filepath.Ext(base)) {
	case ".go", ".ts", ".tsx", ".mjs", ".tf":
		return "//"
	case ".sh", ".rego":
		return "#"
	case ".sql":
		return "--"
	case "":
		if strings.HasPrefix(filepath.ToSlash(file), ".githooks/") {
			return "#"
		}
	}
	return ""
}

var skipFiles = map[string]bool{"apps/web/next-env.d.ts": true}

// sourceFiles lists tracked and not-ignored files that need a header.
func sourceFiles() []string {
	out, err := exec.CommandContext(context.Background(), "git", "ls-files", "-co", "--exclude-standard").Output()
	must(err)
	var files []string
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f == "" || skipFiles[f] || strings.HasPrefix(f, "LICENSES/") || strings.Contains(f, "node_modules/") {
			continue
		}
		if _, err := os.Stat(f); err != nil {
			continue // deleted but still listed
		}
		if commentPrefix(f) != "" && !generated(f) {
			files = append(files, f)
		}
	}
	return files
}

func generated(file string) bool {
	b, err := os.ReadFile(file) // #nosec G304 -- path comes from the local Git file inventory.
	if err != nil {
		return false
	}
	head := string(b)
	if len(head) > 600 {
		head = head[:600]
	}
	return strings.Contains(head, "Code generated") || strings.Contains(head, "DO NOT EDIT")
}

// headerLine returns the file's SPDX line and its index, if any.
func headerLine(lines []string) (int, string) {
	for i := 0; i < len(lines) && i < 4; i++ {
		if strings.Contains(lines[i], spdxTag) {
			return i, lines[i]
		}
	}
	return -1, ""
}

func headers(apply bool) {
	var missing []string
	changed := 0
	for _, f := range sourceFiles() {
		b, err := os.ReadFile(f) // #nosec G304 -- path comes from the local Git file inventory.
		must(err)
		lines := strings.Split(string(b), "\n")
		want := commentPrefix(f) + " " + spdxTag + " " + spdxID
		if i, got := headerLine(lines); i >= 0 {
			if got == want {
				continue
			}
			if apply {
				lines[i] = want
				must(os.WriteFile(f, []byte(strings.Join(lines, "\n")), 0o644)) // #nosec G306 G703 -- Git inventory paths stay inside the repository; source files are public.
				changed++
				continue
			}
			missing = append(missing, f+" (wrong licence identifier)")
			continue
		}
		if !apply {
			missing = append(missing, f)
			continue
		}
		at := 0
		if strings.HasPrefix(lines[0], "#!") {
			at = 1 // keep the interpreter line first
		}
		insert := []string{want}
		if at == 0 {
			insert = append(insert, "")
		}
		out := append(append(append([]string{}, lines[:at]...), insert...), lines[at:]...)
		must(os.WriteFile(f, []byte(strings.Join(out, "\n")), 0o644)) // #nosec G306 G703 -- Git inventory paths stay inside the repository; source files are public.
		changed++
	}
	if apply {
		fmt.Printf("updated %d files\n", changed)
		return
	}
	if len(missing) > 0 {
		fail("source files without the licence header `" + spdxTag + " " + spdxID + "` (run `make license-headers`):\n  " + strings.Join(missing, "\n  "))
	}
	fmt.Println("ok: every source file carries the licence header")
}
