package app

import (
	"fmt"

	"github.com/Helixar-AI/ReleaseGuard/internal/pack"
)

// Pack packages the artifact directory into a canonical archive.
func Pack(path, out, format string) error {
	fmt.Printf("releaseguard pack %s -> %s [format=%s]\n\n", path, out, format)

	var err error
	switch format {
	case "zip":
		err = pack.ZipDir(path, out)
	default:
		err = pack.TarGzDir(path, out)
	}
	if err != nil {
		return fmt.Errorf("packaging: %w", err)
	}

	fmt.Printf("  Archive written: %s\n", out)
	return nil
}
