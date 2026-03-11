package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// Reporter writes scan results in the specified format.
type Reporter struct {
	format string
	out    string // "" means stdout
}

// NewReporter returns a Reporter for the given format and output path.
func NewReporter(format, out string) *Reporter {
	return &Reporter{format: format, out: out}
}

// Write serialises result to the configured output.
func (r *Reporter) Write(result *model.ScanResult) error {
	var w io.Writer = os.Stdout
	if r.out != "" {
		f, err := os.Create(r.out)
		if err != nil {
			return fmt.Errorf("opening output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(r.format) {
	case "json":
		return writeJSON(w, result)
	case "sarif":
		return writeSARIF(w, result)
	case "markdown", "md":
		return writeMarkdown(w, result)
	case "html":
		return writeHTML(w, result)
	default:
		return writeCLI(w, result)
	}
}

func writeJSON(w io.Writer, result *model.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func writeCLI(w io.Writer, result *model.ScanResult) error {
	if result.Manifest != nil {
		fmt.Fprintf(w, "Files scanned: %d  (%s)\n\n", result.Manifest.TotalFiles, result.InputPath)
	}

	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
	} else {
		fmt.Fprintf(w, "Findings (%d):\n", len(result.Findings))
		fmt.Fprintf(w, "  %-10s %-12s %-30s %s\n", "SEVERITY", "CATEGORY", "PATH", "MESSAGE")
		fmt.Fprintln(w, "  "+strings.Repeat("-", 80))
		for _, f := range result.Findings {
			path := f.Path
			if len(path) > 30 {
				path = "..." + path[len(path)-27:]
			}
			fmt.Fprintf(w, "  %-10s %-12s %-30s %s\n",
				strings.ToUpper(f.Severity),
				f.Category,
				path,
				f.Message,
			)
		}
	}

	if result.PolicyResult != nil {
		fmt.Fprintf(w, "\nPolicy result: %s\n", strings.ToUpper(string(result.PolicyResult.Result)))
	}
	return nil
}

func writeSARIF(w io.Writer, result *model.ScanResult) error {
	type sarifResult struct {
		RuleID  string `json:"ruleId"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []map[string]interface{} `json:"locations"`
	}
	type sarifRun struct {
		Tool    map[string]interface{} `json:"tool"`
		Results []sarifResult          `json:"results"`
	}
	type sarifDoc struct {
		Version string     `json:"version"`
		Schema  string     `json:"$schema"`
		Runs    []sarifRun `json:"runs"`
	}

	var results []sarifResult
	for _, f := range result.Findings {
		sr := sarifResult{RuleID: f.ID}
		sr.Message.Text = f.Message
		sr.Locations = []map[string]interface{}{
			{"physicalLocation": map[string]interface{}{
				"artifactLocation": map[string]interface{}{"uri": f.Path},
			}},
		}
		results = append(results, sr)
	}

	doc := sarifDoc{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: map[string]interface{}{
				"driver": map[string]interface{}{
					"name":           "releaseguard",
					"informationUri": "https://github.com/Helixar-AI/ReleaseGuard",
					"version":        "dev",
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func writeMarkdown(w io.Writer, result *model.ScanResult) error {
	fmt.Fprintln(w, "# ReleaseGuard Scan Report")
	fmt.Fprintf(w, "\n**Path:** `%s`\n\n", result.InputPath)
	if result.PolicyResult != nil {
		fmt.Fprintf(w, "**Policy result:** `%s`\n\n", strings.ToUpper(string(result.PolicyResult.Result)))
	}
	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "_No findings._")
		return nil
	}
	fmt.Fprintf(w, "## Findings (%d)\n\n", len(result.Findings))
	fmt.Fprintln(w, "| Severity | Category | Path | Message |")
	fmt.Fprintln(w, "|----------|----------|------|---------|")
	for _, f := range result.Findings {
		fmt.Fprintf(w, "| %s | %s | `%s` | %s |\n", f.Severity, f.Category, f.Path, f.Message)
	}
	return nil
}

func writeHTML(w io.Writer, result *model.ScanResult) error {
	fmt.Fprintln(w, `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>ReleaseGuard Report</title>
<style>body{font-family:sans-serif;max-width:900px;margin:2rem auto}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}
th{background:#f4f4f4}.critical{color:#c00}.high{color:#e65c00}.medium{color:#997a00}.low{color:#555}
</style></head><body>
<h1>ReleaseGuard Scan Report</h1>`)
	fmt.Fprintf(w, "<p><strong>Path:</strong> <code>%s</code></p>\n", result.InputPath)
	if result.PolicyResult != nil {
		fmt.Fprintf(w, "<p><strong>Policy:</strong> %s</p>\n", strings.ToUpper(string(result.PolicyResult.Result)))
	}
	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "<p>No findings.</p>")
	} else {
		fmt.Fprintf(w, "<h2>Findings (%d)</h2>\n<table>\n<tr><th>Severity</th><th>Category</th><th>Path</th><th>Message</th></tr>\n", len(result.Findings))
		for _, f := range result.Findings {
			fmt.Fprintf(w, "<tr><td class=%q>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>\n",
				f.Severity, strings.ToUpper(f.Severity), f.Category, f.Path, f.Message)
		}
		fmt.Fprintln(w, "</table>")
	}
	fmt.Fprintln(w, "</body></html>")
	return nil
}
