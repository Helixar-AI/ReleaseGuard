package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Helixar-AI/ReleaseGuard/internal/model"
	"github.com/Helixar-AI/ReleaseGuard/internal/report"
)

// Report exports findings from a previous check run in the specified format.
func Report(path, format, out string) error {
	fmt.Printf("releaseguard report %s [format=%s]\n\n", path, format)

	// Load existing scan result from evidence directory
	evidenceDir := "./.releaseguard"
	resultFile := filepath.Join(evidenceDir, "result.json")

	data, err := os.ReadFile(resultFile)
	if err != nil {
		return fmt.Errorf("no scan result found at %s — run `releaseguard check` first", resultFile)
	}

	var result model.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing scan result: %w", err)
	}

	reporter := report.NewReporter(format, out)
	return reporter.Write(&result)
}
