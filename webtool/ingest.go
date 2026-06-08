package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	scanner "github.com/checkmarx/2ms/v5/pkg"
)

// maxFileBytes caps the size of an individual file we will read into memory and
// scan. Larger files are skipped (they are almost always assets/binaries).
const maxFileBytes = 10 << 20 // 10 MiB

// ingestSource resolves a JSON-based scan request (local path or Git URL) into a
// root directory on disk plus an optional cleanup function.
func ingestSource(opts ScanOptions) (root, desc string, cleanup func(), err error) {
	switch {
	case opts.Path != "":
		info, statErr := os.Stat(opts.Path)
		if statErr != nil {
			return "", "", nil, fmt.Errorf("path not accessible: %w", statErr)
		}
		if !info.IsDir() {
			return "", "", nil, errors.New("path must be a directory")
		}
		return opts.Path, "path: " + opts.Path, nil, nil
	case opts.GitURL != "":
		return cloneGit(opts.GitURL)
	default:
		return "", "", nil, errors.New("provide a path, a gitUrl, or upload a zip")
	}
}

// cloneGit shallow-clones a repository into a temp dir.
func cloneGit(rawURL string) (root, desc string, cleanup func(), err error) {
	u, parseErr := url.Parse(rawURL)
	if parseErr != nil || (u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "git") {
		return "", "", nil, errors.New("invalid git URL (use https://...)")
	}
	dir, err := os.MkdirTemp("", "2ms-web-git-")
	if err != nil {
		return "", "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }

	cmd := exec.Command("git", "clone", "--depth", "1", "--no-tags", rawURL, dir) //nolint:gosec // URL validated above
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, runErr := cmd.CombinedOutput(); runErr != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("git clone failed: %s", strings.TrimSpace(string(out)))
	}
	return dir, "git: " + rawURL, cleanup, nil
}

// ingestUpload handles a multipart zip upload, extracting it to a temp dir and
// reading the precision toggles from the form fields.
func (s *Server) ingestUpload(r *http.Request, opts ScanOptions) (root, desc string, cleanup func(), out ScanOptions, err error) {
	if err = r.ParseMultipartForm(32 << 20); err != nil {
		return "", "", nil, opts, fmt.Errorf("parse upload: %w", err)
	}
	applyFormOptions(r, &opts)

	file, header, err := r.FormFile("file")
	if err != nil {
		return "", "", nil, opts, errors.New("missing 'file' (zip) in upload")
	}
	defer func() { _ = file.Close() }()

	tmpZip, err := os.CreateTemp("", "2ms-web-*.zip")
	if err != nil {
		return "", "", nil, opts, err
	}
	defer func() {
		_ = tmpZip.Close()
		_ = os.Remove(tmpZip.Name())
	}()

	if _, err = io.Copy(tmpZip, io.LimitReader(file, maxUploadBytes)); err != nil {
		return "", "", nil, opts, err
	}

	dir, err := os.MkdirTemp("", "2ms-web-zip-")
	if err != nil {
		return "", "", nil, opts, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }

	if err = unzip(tmpZip.Name(), dir); err != nil {
		cleanup()
		return "", "", nil, opts, fmt.Errorf("unzip: %w", err)
	}
	return dir, "zip: " + header.Filename, cleanup, opts, nil
}

func applyFormOptions(r *http.Request, opts *ScanOptions) {
	if v := r.FormValue("applyExcludes"); v != "" {
		opts.ApplyExcludes = v == "true" || v == "1" || v == "on"
	}
	if v := r.FormValue("applyFilters"); v != "" {
		opts.ApplyFilters = v == "true" || v == "1" || v == "on"
	}
	if v := r.FormValue("applyFeedback"); v != "" {
		opts.ApplyFeedback = v == "true" || v == "1" || v == "on"
	}
	if v := r.FormValue("aggressiveRecall"); v != "" {
		opts.AggressiveRecall = v == "true" || v == "1" || v == "on"
	}
	if v := r.FormValue("withValidation"); v != "" {
		opts.WithValidation = v == "true" || v == "1" || v == "on"
	}
	if v := r.FormValue("minEntropy"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			opts.MinEntropy = f
		}
	}
}

// unzip extracts src into dest, guarding against path traversal (zip slip).
func unzip(src, dest string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() { _ = zr.Close() }()

	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		target := filepath.Join(destAbs, f.Name) //nolint:gosec // checked below
		if !strings.HasPrefix(target, destAbs+string(os.PathSeparator)) && target != destAbs {
			return fmt.Errorf("illegal path in zip: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if mkErr := os.MkdirAll(target, 0o750); mkErr != nil {
				return mkErr
			}
			continue
		}
		if err = extractZipFile(f, target); err != nil {
			return err
		}
	}
	return nil
}

func extractZipFile(f *zip.File, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	// Cap per-file extraction to avoid zip bombs.
	if _, err = io.Copy(out, io.LimitReader(rc, maxUploadBytes)); err != nil {
		return err
	}
	return nil
}

// collectScanItems walks root, applying Layer 1 excludes, and reads eligible
// files into scan items. Returns items plus ingested/excluded counts.
func collectScanItems(root string, applyExcludes bool) (items []scanner.ScanItem, ingested, excluded int, err error) {
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable entries
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		if d.IsDir() {
			if applyExcludes && rel != "." && isExcludedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if applyExcludes && isExcludedFile(rel) {
			excluded++
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil || info.Size() == 0 || info.Size() > maxFileBytes {
			excluded++
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			excluded++
			return nil
		}
		if looksBinary(data) || (applyExcludes && looksMinified(data)) {
			excluded++
			return nil
		}
		content := string(data)
		items = append(items, scanner.ScanItem{
			Content: &content,
			ID:      rel,
			Source:  rel,
		})
		ingested++
		return nil
	})
	return items, ingested, excluded, walkErr
}
