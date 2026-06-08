package main

import (
	"bytes"
	"path/filepath"
	"strings"
)

// Layer 1: ingestion excludes. These remove the dominant source of false
// positives observed in practice -- build outputs, dependency trees, caches,
// generated/minified assets, lockfiles and binaries -- before the engine ever
// sees them.

// excludedDirs are directory names skipped anywhere in the tree.
var excludedDirs = map[string]struct{}{
	".git":             {},
	".svn":             {},
	".hg":              {},
	"node_modules":     {},
	"bower_components": {},
	"vendor":           {},
	"dist":             {},
	"build":            {},
	"out":              {},
	"target":           {},
	"bin":              {},
	"obj":              {},
	".angular":         {},
	".next":            {},
	".nuxt":            {},
	".svelte-kit":      {},
	".cache":           {},
	".parcel-cache":    {},
	".gradle":          {},
	".idea":            {},
	".vscode":          {},
	".terraform":       {},
	"__pycache__":      {},
	".venv":            {},
	"venv":             {},
	"env":              {},
	"coverage":         {},
	".nyc_output":      {},
	".pytest_cache":    {},
	".mvn":             {},
	"Pods":             {},
}

// excludedExts are file extensions that never contain scannable secrets.
var excludedExts = map[string]struct{}{
	// images / media
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".bmp": {}, ".ico": {}, ".webp": {},
	".svg": {}, ".tif": {}, ".tiff": {}, ".psd": {},
	".mp3": {}, ".mp4": {}, ".wav": {}, ".avi": {}, ".mov": {}, ".mkv": {}, ".webm": {},
	// fonts
	".woff": {}, ".woff2": {}, ".ttf": {}, ".otf": {}, ".eot": {},
	// archives
	".zip": {}, ".tar": {}, ".gz": {}, ".tgz": {}, ".bz2": {}, ".xz": {}, ".7z": {}, ".rar": {},
	// compiled / binary
	".class": {}, ".jar": {}, ".war": {}, ".so": {}, ".dll": {}, ".dylib": {}, ".exe": {},
	".o": {}, ".a": {}, ".pyc": {}, ".pyo": {}, ".wasm": {}, ".bin": {}, ".dat": {},
	// docs / office (binary)
	".pdf": {}, ".doc": {}, ".docx": {}, ".xls": {}, ".xlsx": {}, ".ppt": {}, ".pptx": {},
	".pages": {}, ".key": {}, ".numbers": {},
	// build/generated artifacts
	".map": {}, ".pack": {}, ".min.js": {}, ".min.css": {},
	// misc noise
	".lock": {}, ".log": {}, ".DS_Store": {},
}

// excludedNames are exact filenames (lockfiles etc.) that are skipped.
var excludedNames = map[string]struct{}{
	"package-lock.json":   {},
	"yarn.lock":           {},
	"pnpm-lock.yaml":      {},
	"npm-shrinkwrap.json": {},
	"go.sum":              {},
	"cargo.lock":          {},
	"poetry.lock":         {},
	"pipfile.lock":        {},
	"composer.lock":       {},
	"gemfile.lock":        {},
	".ds_store":           {},
}

func isExcludedDir(name string) bool {
	_, ok := excludedDirs[name]
	return ok
}

// isExcludedFile reports whether a file (given by its path relative to the scan
// root) should be skipped by Layer 1.
func isExcludedFile(rel string) bool {
	base := strings.ToLower(filepath.Base(rel))
	if _, ok := excludedNames[base]; ok {
		return true
	}
	// Multi-part extensions first (e.g. ".min.js").
	for ext := range excludedExts {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return false
}

// looksBinary reports whether a buffer is likely binary (contains NUL bytes or a
// high proportion of non-printable characters in its head).
func looksBinary(data []byte) bool {
	head := data
	if len(head) > 8000 {
		head = head[:8000]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return true
	}
	nonPrintable := 0
	for _, b := range head {
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			nonPrintable++
		}
	}
	return len(head) > 0 && nonPrintable*100/len(head) > 30
}

// looksMinified reports whether content appears minified or machine-generated,
// based on very long average line length. These files (webpack bundles, minified
// JS/CSS, serialized caches) are a major false-positive source.
func looksMinified(data []byte) bool {
	const sample = 65536
	head := data
	if len(head) > sample {
		head = head[:sample]
	}
	lines := bytes.Count(head, []byte{'\n'}) + 1
	avg := len(head) / lines
	if avg > 2000 {
		return true
	}
	// Single enormous line.
	if lines <= 2 && len(data) > 50000 {
		return true
	}
	return false
}
