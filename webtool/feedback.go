package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Layer 3: a persistent learned-false-positive allowlist. When a user marks a
// finding as a false positive, we store a one-way signature (rule + value hash)
// so future scans -- across any repo -- automatically suppress the same secret
// without persisting the secret value in plaintext.

// FeedbackStore persists FP signatures to a JSON file.
type FeedbackStore struct {
	path string

	mu   sync.RWMutex
	sigs map[string]bool
}

type feedbackFile struct {
	Signatures []string `json:"signatures"`
}

// NewFeedbackStore loads (or creates) the allowlist under dataDir.
func NewFeedbackStore(dataDir string) (*FeedbackStore, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, err
	}
	s := &FeedbackStore{
		path: filepath.Join(dataDir, "feedback.json"),
		sigs: make(map[string]bool),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FeedbackStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var ff feedbackFile
	if err := json.Unmarshal(data, &ff); err != nil {
		return err
	}
	for _, sig := range ff.Signatures {
		s.sigs[sig] = true
	}
	return nil
}

func (s *FeedbackStore) save() error {
	ff := feedbackFile{}
	for sig := range s.sigs {
		ff.Signatures = append(ff.Signatures, sig)
	}
	data, err := json.MarshalIndent(ff, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

func signature(f *Finding) string {
	sum := sha256.Sum256([]byte(f.RuleID + "\x00" + f.RawValue))
	return hex.EncodeToString(sum[:])
}

// Contains reports whether a finding has been marked as a false positive before.
func (s *FeedbackStore) Contains(f *Finding) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sigs[signature(f)]
}

// Add records a finding as a false positive and persists the allowlist.
func (s *FeedbackStore) Add(f *Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sigs[signature(f)] = true
	return s.save()
}

// Remove undoes a previous false-positive mark.
func (s *FeedbackStore) Remove(f *Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sigs, signature(f))
	return s.save()
}
