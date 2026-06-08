package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/checkmarx/2ms/v5/lib/reporting"
)

//go:embed static/*
var staticFS embed.FS

// maxUploadBytes caps zip uploads (2 GiB).
const maxUploadBytes = 2 << 30

// Server holds shared state for the web tool.
type Server struct {
	mux      *http.ServeMux
	feedback *FeedbackStore

	mu   sync.RWMutex
	jobs map[string]*Job
}

// NewServer builds a Server, loading the persistent feedback allowlist.
func NewServer(dataDir string) (*Server, error) {
	fb, err := NewFeedbackStore(dataDir)
	if err != nil {
		return nil, fmt.Errorf("init feedback store: %w", err)
	}
	s := &Server{
		mux:      http.NewServeMux(),
		feedback: fb,
		jobs:     make(map[string]*Job),
	}
	s.routes()
	return s, nil
}

// Listen starts the HTTP server on addr.
func (s *Server) Listen(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 15 * time.Second,
	}
	return srv.ListenAndServe()
}

// Serve starts the HTTP server on an already-bound listener.
func (s *Server) Serve(ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.mux,
		ReadHeaderTimeout: 15 * time.Second,
	}
	return srv.Serve(ln)
}

func (s *Server) routes() {
	sub, _ := fs.Sub(staticFS, "static")
	s.mux.Handle("/", http.FileServer(http.FS(sub)))
	s.mux.HandleFunc("/api/scan", s.handleScan)
	s.mux.HandleFunc("/api/scan/", s.handleJob)
	s.mux.HandleFunc("/api/feedback", s.handleFeedback)
	s.mux.HandleFunc("/api/export/", s.handleExport)
}

// handleScan accepts a new scan: multipart (zip) or JSON ({path}/{gitUrl}).
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	opts := defaultScanOptions()
	var (
		rootDir string
		desc    string
		cleanup func()
		err     error
	)

	ct := r.Header.Get("Content-Type")
	if len(ct) >= 19 && ct[:19] == "multipart/form-data" {
		rootDir, desc, cleanup, opts, err = s.ingestUpload(r, opts)
	} else {
		if decErr := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&opts); decErr != nil && decErr != io.EOF {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		rootDir, desc, cleanup, err = ingestSource(opts)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	job := &Job{
		ID:         newID(),
		Status:     StatusQueued,
		SourceDesc: desc,
		StartedAt:  time.Now(),
	}
	s.mu.Lock()
	s.jobs[job.ID] = job
	s.mu.Unlock()

	go s.runScan(job, rootDir, opts, cleanup)

	writeJSON(w, http.StatusAccepted, map[string]string{"id": job.ID})
}

// runScan executes the full pipeline for a job in the background.
func (s *Server) runScan(job *Job, rootDir string, opts ScanOptions, cleanup func()) {
	if cleanup != nil {
		defer cleanup()
	}
	s.update(job, StatusRunning, 10, "Collecting files")

	items, ingested, excluded, err := collectScanItems(rootDir, opts.ApplyExcludes)
	if err != nil {
		s.fail(job, fmt.Sprintf("collect files: %v", err))
		return
	}

	s.update(job, StatusRunning, 35, fmt.Sprintf("Scanning %d files", ingested))

	report, err := runEngine(context.Background(), items, opts)
	if err != nil {
		s.fail(job, fmt.Sprintf("scan engine: %v", err))
		return
	}

	s.update(job, StatusRunning, 80, "Scoring findings")

	result := s.buildResult(report, opts)
	result.FilesIngested = ingested
	result.FilesExcluded = excluded
	result.TotalItemsScanned = report.GetTotalItemsScanned()

	s.mu.Lock()
	job.Result = result
	job.Status = StatusDone
	job.Progress = 100
	job.Message = "Done"
	job.FinishedAt = time.Now()
	s.mu.Unlock()
}

// buildResult converts the raw report into scored, filtered findings by running
// the Layer 2 confidence engine and Layer 3 learned-allowlist over each secret.
func (s *Server) buildResult(report reporting.IReport, opts ScanOptions) *ScanResult {
	res := &ScanResult{
		ByConfidence: map[string]int{ConfidenceHigh: 0, ConfidenceMedium: 0, ConfidenceLow: 0},
	}
	// kept maps a dedup key to the surfaced finding currently held for it, so we
	// can prefer the highest-confidence match when several rules hit one spot.
	kept := make(map[string]*Finding)

	for _, list := range report.GetResults() {
		for _, sec := range list {
			res.RawFindings++
			f := toFinding(sec)

			// Layer 2: confidence scoring + FP gates.
			if opts.ApplyFilters {
				scoreFinding(f, opts.MinEntropy)
			} else {
				f.Confidence = ConfidenceHigh
			}

			// Layer 3: learned false-positive allowlist.
			if opts.ApplyFeedback && s.feedback.Contains(f) {
				f.Suppressed = true
				f.Learned = true
				f.FilterReason = "marked as false positive previously"
			}

			// Dedup by value + location (file and line), independent of which rule
			// matched. The same secret in a different file or line stays distinct;
			// at one spot we keep the highest-confidence row (e.g. a provider rule
			// over the broad keyword rule).
			if !f.Suppressed {
				key := fmt.Sprintf("%s\x00%s\x00%d", f.RawValue, f.Source, f.StartLine)
				if prev, ok := kept[key]; ok {
					if confRank(f.Confidence) < confRank(prev.Confidence) {
						markDuplicate(prev) // new one is better; demote the old
						kept[key] = f
					} else {
						markDuplicate(f)
					}
				} else {
					kept[key] = f
				}
			}

			res.Findings = append(res.Findings, f)
		}
	}

	for _, f := range res.Findings {
		if f.Suppressed {
			res.Suppressed++
		} else {
			res.Surfaced++
			res.ByConfidence[f.Confidence]++
		}
	}

	sort.SliceStable(res.Findings, func(i, j int) bool {
		fi, fj := res.Findings[i], res.Findings[j]
		if fi.Suppressed != fj.Suppressed {
			return !fi.Suppressed
		}
		return confRank(fi.Confidence) < confRank(fj.Confidence)
	})
	return res
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/scan/"):]
	s.mu.RLock()
	job, ok := s.jobs[id]
	s.mu.RUnlock()
	if !ok {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		JobID     string `json:"jobId"`
		FindingID string `json:"findingId"`
		Undo      bool   `json:"undo"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	s.mu.RLock()
	job, ok := s.jobs[req.JobID]
	s.mu.RUnlock()
	if !ok || job.Result == nil {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	var target *Finding
	for _, f := range job.Result.Findings {
		if f.ID == req.FindingID {
			target = f
			break
		}
	}
	if target == nil {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}
	if req.Undo {
		if err := s.feedback.Remove(target); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else if err := s.feedback.Add(target); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/export/"):]
	s.mu.RLock()
	job, ok := s.jobs[id]
	s.mu.RUnlock()
	if !ok || job.Result == nil {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	format := r.URL.Query().Get("format")
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=2ms-report.csv")
		writeCSV(w, job.Result)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=2ms-report.json")
		writeJSON(w, http.StatusOK, job.Result)
	}
}

// --- helpers ---

func (s *Server) update(job *Job, status string, progress int, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job.Status = status
	job.Progress = progress
	job.Message = msg
}

func (s *Server) fail(job *Job, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job.Status = StatusError
	job.Error = msg
	job.FinishedAt = time.Now()
}

func defaultScanOptions() ScanOptions {
	return ScanOptions{
		ApplyExcludes:    true,
		ApplyFilters:     true,
		ApplyFeedback:    true,
		AggressiveRecall: true,
		MinEntropy:       3.0,
	}
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	_ = enc.Encode(v)
}

func writeCSV(w io.Writer, res *ScanResult) {
	fmt.Fprintln(w, "confidence,severity,rule,source,startLine,value,suppressed,reason")
	findings := append([]*Finding(nil), res.Findings...)
	sort.Slice(findings, func(i, j int) bool {
		return confRank(findings[i].Confidence) < confRank(findings[j].Confidence)
	})
	for _, f := range findings {
		fmt.Fprintf(w, "%s,%s,%s,%q,%d,%q,%t,%q\n",
			f.Confidence, f.Severity, f.RuleName, f.Source, f.StartLine, f.RawValue, f.Suppressed, f.FilterReason)
	}
}

// markDuplicate suppresses a finding that duplicates a higher-or-equal
// confidence match at the same location.
func markDuplicate(f *Finding) {
	f.Suppressed = true
	if f.FilterReason == "" {
		f.FilterReason = "duplicate of the same location"
	}
}

func confRank(c string) int {
	switch c {
	case ConfidenceHigh:
		return 0
	case ConfidenceMedium:
		return 1
	default:
		return 2
	}
}
