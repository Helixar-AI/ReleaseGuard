package sbom

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// parsePythonLockfile tries each Python lock file format in priority order.
func parsePythonLockfile(root string) ([]model.SBOMComponent, error) {
	// Pipfile.lock (JSON, most structured)
	if comps, err := parsePipfileLock(root + "/Pipfile.lock"); err == nil {
		return comps, nil
	}
	// poetry.lock (TOML-like)
	if comps, err := parsePoetryLock(root + "/poetry.lock"); err == nil {
		return comps, nil
	}
	// requirements.txt (plain text, lowest priority)
	if comps, err := parseRequirementsTxt(root + "/requirements.txt"); err == nil {
		return comps, nil
	}
	return nil, nil
}

// --- Pipfile.lock ---

type pipfileLock struct {
	Default map[string]pipfileEntry `json:"default"`
	Develop map[string]pipfileEntry `json:"develop"`
}

type pipfileEntry struct {
	Version string `json:"version"` // "==1.2.3"
}

func parsePipfileLock(path string) ([]model.SBOMComponent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lf pipfileLock
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("Pipfile.lock: %w", err)
	}

	var comps []model.SBOMComponent
	for name, entry := range lf.Default {
		version := strings.TrimPrefix(entry.Version, "==")
		if version == "" {
			continue
		}
		comps = append(comps, model.SBOMComponent{
			Name:       name,
			Version:    version,
			PackageURL: fmt.Sprintf("pkg:pypi/%s@%s", strings.ToLower(name), version),
			Ecosystem:  "python",
		})
	}
	for name, entry := range lf.Develop {
		version := strings.TrimPrefix(entry.Version, "==")
		if version == "" {
			continue
		}
		comps = append(comps, model.SBOMComponent{
			Name:       name,
			Version:    version,
			PackageURL: fmt.Sprintf("pkg:pypi/%s@%s", strings.ToLower(name), version),
			Ecosystem:  "python",
		})
	}
	return comps, nil
}

// --- poetry.lock ---

// parsePoetryLock parses poetry.lock (TOML [[package]] sections) line-by-line.
func parsePoetryLock(path string) ([]model.SBOMComponent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var comps []model.SBOMComponent
	var curName, curVersion string

	flush := func() {
		if curName != "" && curVersion != "" {
			comps = append(comps, model.SBOMComponent{
				Name:       curName,
				Version:    curVersion,
				PackageURL: fmt.Sprintf("pkg:pypi/%s@%s", strings.ToLower(curName), curVersion),
				Ecosystem:  "python",
			})
		}
		curName = ""
		curVersion = ""
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "[[package]]" {
			flush()
			continue
		}

		k, v, ok := splitTOMLKeyValue(trimmed)
		if !ok {
			continue
		}
		switch k {
		case "name":
			curName = v
		case "version":
			curVersion = v
		}
	}
	flush()
	return comps, nil
}

// --- requirements.txt ---

// parseRequirementsTxt parses a pip requirements.txt file.
// Handles lines like:
//
//	requests==2.28.0
//	flask>=2.0.0
//	pillow   (no version)
//	-r other-requirements.txt  (skipped)
func parseRequirementsTxt(path string) ([]model.SBOMComponent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var comps []model.SBOMComponent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip inline comments
		if idx := strings.Index(line, " #"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// Split on version operators
		name, version := splitRequirement(line)
		if name == "" {
			continue
		}
		purl := fmt.Sprintf("pkg:pypi/%s", strings.ToLower(name))
		if version != "" {
			purl += "@" + version
		}
		comps = append(comps, model.SBOMComponent{
			Name:       name,
			Version:    version,
			PackageURL: purl,
			Ecosystem:  "python",
		})
	}
	return comps, nil
}

// splitRequirement splits "requests==2.28.0" into ("requests", "2.28.0").
func splitRequirement(line string) (name, version string) {
	// Handle extras like "requests[security]==2.28.0"
	if idx := strings.Index(line, "["); idx > 0 {
		line = line[:idx] + line[strings.Index(line, "]")+1:]
	}
	for _, op := range []string{"===", "~=", "!=", "==", ">=", "<=", ">", "<", "@"} {
		if idx := strings.Index(line, op); idx > 0 {
			return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+len(op):])
		}
	}
	return strings.TrimSpace(line), ""
}

// splitTOMLKeyValue parses a simple `key = "value"` or `key = value` TOML line.
func splitTOMLKeyValue(line string) (key, value string, ok bool) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	// Strip surrounding quotes
	value = strings.Trim(value, `"'`)
	return key, value, true
}
