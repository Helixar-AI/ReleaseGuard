package sbom

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// parseGoMod parses go.sum to produce a component list for the Go ecosystem.
// Each line of go.sum has the format: module version hash
// Lines ending in /go.mod describe the module's go.mod file and are skipped
// (we only want the source archive entries).
func parseGoMod(root string) ([]model.SBOMComponent, error) {
	path := root + "/go.sum"
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := make(map[string]bool)
	var comps []model.SBOMComponent

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		modPath := parts[0]
		modVersion := parts[1]

		// Skip go.mod-only entries
		if strings.HasSuffix(modVersion, "/go.mod") {
			continue
		}

		key := modPath + "@" + modVersion
		if seen[key] {
			continue
		}
		seen[key] = true

		var hashes []model.Hash
		if len(parts) >= 3 {
			// hash format: "h1:base64=="
			h := parts[2]
			if idx := strings.Index(h, ":"); idx > 0 {
				hashes = append(hashes, model.Hash{
					Algorithm: "sha256-dirhash",
					Value:     h[idx+1:],
				})
			}
		}

		comps = append(comps, model.SBOMComponent{
			Name:       modPath,
			Version:    modVersion,
			PackageURL: fmt.Sprintf("pkg:golang/%s@%s", modPath, modVersion),
			Ecosystem:  "go",
			Hashes:     hashes,
		})
	}
	return comps, nil
}
