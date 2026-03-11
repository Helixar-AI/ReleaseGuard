package sbom

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// parseNodeLockfile attempts to parse package-lock.json (v1/v2/v3) or yarn.lock.
func parseNodeLockfile(root string) ([]model.SBOMComponent, error) {
	// Try package-lock.json first (npm)
	if comps, err := parsePackageLock(filepath.Join(root, "package-lock.json")); err == nil {
		return comps, nil
	}

	// Try yarn.lock
	if comps, err := parseYarnLock(filepath.Join(root, "yarn.lock")); err == nil {
		return comps, nil
	}

	// Try pnpm-lock.yaml (basic — just record presence)
	if _, err := os.Stat(filepath.Join(root, "pnpm-lock.yaml")); err == nil {
		return parsePnpmLock(filepath.Join(root, "pnpm-lock.yaml"))
	}

	return nil, nil
}

// --- package-lock.json ---

type packageLockFile struct {
	Name            string                        `json:"name"`
	Version         string                        `json:"version"`
	LockfileVersion int                           `json:"lockfileVersion"`
	Packages        map[string]pkgLockEntry       `json:"packages"`     // v2/v3
	Dependencies    map[string]pkgLockDepEntry    `json:"dependencies"` // v1
}

type pkgLockEntry struct {
	Version   string   `json:"version"`
	License   string   `json:"license"`
	Integrity string   `json:"integrity"`
	Dev       bool     `json:"dev"`
	Licenses  []string `json:"licenses"`
}

type pkgLockDepEntry struct {
	Version   string `json:"version"`
	Integrity string `json:"integrity"`
	Dev       bool   `json:"dev"`
}

func parsePackageLock(path string) ([]model.SBOMComponent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lf packageLockFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("package-lock.json: %w", err)
	}

	var comps []model.SBOMComponent

	if lf.LockfileVersion >= 2 && len(lf.Packages) > 0 {
		// v2/v3: packages map keys are like "node_modules/react"
		for key, entry := range lf.Packages {
			if key == "" {
				continue // root package
			}
			name := strings.TrimPrefix(key, "node_modules/")
			if entry.Version == "" {
				continue
			}
			lic := entry.License
			if lic == "" && len(entry.Licenses) > 0 {
				lic = entry.Licenses[0]
			}
			comps = append(comps, model.SBOMComponent{
				Name:       name,
				Version:    entry.Version,
				PackageURL: fmt.Sprintf("pkg:npm/%s@%s", name, entry.Version),
				Ecosystem:  "node",
				Licenses:   licensesToSlice(lic),
				Hashes:     integrityToHashes(entry.Integrity),
			})
		}
	} else if len(lf.Dependencies) > 0 {
		// v1: dependencies map
		for name, dep := range lf.Dependencies {
			if dep.Version == "" {
				continue
			}
			comps = append(comps, model.SBOMComponent{
				Name:       name,
				Version:    dep.Version,
				PackageURL: fmt.Sprintf("pkg:npm/%s@%s", name, dep.Version),
				Ecosystem:  "node",
				Hashes:     integrityToHashes(dep.Integrity),
			})
		}
	}

	return comps, nil
}

// --- yarn.lock ---

// parseYarnLock parses yarn.lock v1 format (classic yarn).
// Each block looks like:
//
//	react@^18.2.0:
//	  version "18.2.0"
//	  resolved "https://..."
//	  integrity sha512-...
func parseYarnLock(path string) ([]model.SBOMComponent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var comps []model.SBOMComponent
	var currentName string
	var currentVersion string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			if currentName != "" && currentVersion != "" {
				comps = append(comps, model.SBOMComponent{
					Name:       currentName,
					Version:    currentVersion,
					PackageURL: fmt.Sprintf("pkg:npm/%s@%s", currentName, currentVersion),
					Ecosystem:  "node",
				})
			}
			currentName = ""
			currentVersion = ""
			continue
		}

		// Block header: "react@^18.2.0:" or "\"@scope/pkg@^1.0.0\":"
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			// Extract the first specifier's package name
			header := strings.TrimSuffix(strings.TrimSpace(line), ":")
			// Take the first entry (comma-separated)
			first := strings.SplitN(header, ",", 2)[0]
			first = strings.Trim(first, `"`)
			// Strip the version range from the package name (last @ that isn't at position 0 for scoped)
			if idx := strings.LastIndex(first, "@"); idx > 0 {
				currentName = first[:idx]
			} else {
				currentName = first
			}
			currentVersion = ""
			continue
		}

		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "version ") {
			currentVersion = strings.Trim(strings.TrimPrefix(trimmed, "version "), `"`)
		}
	}

	// Flush last entry
	if currentName != "" && currentVersion != "" {
		comps = append(comps, model.SBOMComponent{
			Name:       currentName,
			Version:    currentVersion,
			PackageURL: fmt.Sprintf("pkg:npm/%s@%s", currentName, currentVersion),
			Ecosystem:  "node",
		})
	}

	return comps, nil
}

// --- pnpm-lock.yaml (minimal) ---

// parsePnpmLock does a line-scan of pnpm-lock.yaml to extract package@version entries.
func parsePnpmLock(path string) ([]model.SBOMComponent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var comps []model.SBOMComponent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// pnpm-lock.yaml has entries like:
		//   /react/18.2.0:
		//   /react@18.2.0:  (newer format)
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "/") || !strings.HasSuffix(trimmed, ":") {
			continue
		}
		entry := strings.TrimSuffix(strings.TrimPrefix(trimmed, "/"), ":")
		// entry is "react/18.2.0" or "react@18.2.0"
		var name, version string
		if idx := strings.LastIndex(entry, "/"); idx > 0 {
			name = entry[:idx]
			version = entry[idx+1:]
		} else if idx := strings.LastIndex(entry, "@"); idx > 0 {
			name = entry[:idx]
			version = entry[idx+1:]
		}
		if name != "" && version != "" {
			comps = append(comps, model.SBOMComponent{
				Name:       name,
				Version:    version,
				PackageURL: fmt.Sprintf("pkg:npm/%s@%s", name, version),
				Ecosystem:  "node",
			})
		}
	}
	return comps, nil
}

// --- helpers ---

func licensesToSlice(lic string) []string {
	if lic == "" {
		return nil
	}
	return []string{lic}
}

// integrityToHashes converts an npm integrity string (e.g. "sha512-abc==") to []model.Hash.
func integrityToHashes(integrity string) []model.Hash {
	if integrity == "" {
		return nil
	}
	idx := strings.Index(integrity, "-")
	if idx < 0 {
		return nil
	}
	return []model.Hash{{Algorithm: integrity[:idx], Value: integrity[idx+1:]}}
}
