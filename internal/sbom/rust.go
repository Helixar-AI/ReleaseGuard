package sbom

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// parseCargoLock parses Cargo.lock (TOML) to produce a component list.
// It uses a simple line-by-line state machine to avoid adding a TOML library dependency.
//
// Cargo.lock [[package]] blocks look like:
//
//	[[package]]
//	name = "serde"
//	version = "1.0.123"
//	source = "registry+https://github.com/rust-lang/crates.io-index"
//	checksum = "abc123..."
func parseCargoLock(root string) ([]model.SBOMComponent, error) {
	path := root + "/Cargo.lock"
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var comps []model.SBOMComponent
	var curName, curVersion, curChecksum string

	flush := func() {
		if curName != "" && curVersion != "" {
			c := model.SBOMComponent{
				Name:       curName,
				Version:    curVersion,
				PackageURL: fmt.Sprintf("pkg:cargo/%s@%s", curName, curVersion),
				Ecosystem:  "rust",
			}
			if curChecksum != "" {
				c.Hashes = []model.Hash{{Algorithm: "sha256", Value: curChecksum}}
			}
			comps = append(comps, c)
		}
		curName = ""
		curVersion = ""
		curChecksum = ""
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "[[package]]" {
			flush()
			continue
		}

		k, v, ok := splitCargoKeyValue(trimmed)
		if !ok {
			continue
		}
		switch k {
		case "name":
			curName = v
		case "version":
			curVersion = v
		case "checksum":
			curChecksum = v
		}
	}
	flush()
	return comps, nil
}

// splitCargoKeyValue parses a Cargo.lock key = "value" line.
func splitCargoKeyValue(line string) (key, value string, ok bool) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	value = strings.Trim(value, `"`)
	return key, value, true
}
