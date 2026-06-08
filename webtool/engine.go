package main

import (
	"context"

	"github.com/checkmarx/2ms/v5/lib/reporting"
	scanner "github.com/checkmarx/2ms/v5/pkg"
)

// pluginName is intentionally not "filesystem"/"git" so the engine treats line
// numbers as relative to the provided fragment content (see getStartAndEndLines).
const pluginName = "webtool"

// runEngine runs the 2ms engine over the provided scan items using the full
// default rule set. The precision pipeline (Layer 2/3) is applied afterwards on
// the returned report, so we keep detection broad here for maximum recall.
func runEngine(ctx context.Context, items []scanner.ScanItem, opts ScanOptions) (reporting.IReport, error) {
	sc := scanner.NewScanner()
	cfg := &scanner.ScanConfig{
		PluginName:     pluginName,
		WithValidation: opts.WithValidation,
		// Sane caps to avoid pathological fragments dominating the report.
		MaxRuleMatchesPerFragment: 50,
		MaxSecretSize:             0,
	}
	if opts.AggressiveRecall {
		cfg.CustomRules = aggressiveRecallRules()
	}
	return sc.Scan(ctx, items, cfg)
}
