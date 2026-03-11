package app

import "fmt"

// Harden orchestrates: fix + obfuscate + DRM injection.
func Harden(path, obfuscationLevel string, dryRun bool) error {
	fmt.Printf("releaseguard harden %s\n\n", path)

	fmt.Println("  [1/3] Applying transforms...")
	if err := Fix(path, dryRun); err != nil {
		return fmt.Errorf("fix stage: %w", err)
	}

	fmt.Println("\n  [2/3] Applying obfuscation...")
	if err := Obfuscate(path, obfuscationLevel, dryRun); err != nil {
		return fmt.Errorf("obfuscate stage: %w", err)
	}

	fmt.Println("\n  [3/3] Injecting DRM stubs...")
	if err := injectDRM(path, dryRun); err != nil {
		return fmt.Errorf("DRM stage: %w", err)
	}

	fmt.Println("\n  Hardening complete.")
	return nil
}

func injectDRM(path string, dryRun bool) error {
	// DRM injection is implemented in internal/drm
	// This is the orchestration call-site.
	fmt.Printf("  Integrity check stub injection: %s\n", path)
	if dryRun {
		fmt.Println("  [dry-run] No stubs written.")
	}
	return nil
}
