package collect

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// DetectMIME returns the MIME type for the file at path using magic bytes.
func DetectMIME(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "application/octet-stream"
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return "application/octet-stream"
	}

	return http.DetectContentType(buf[:n])
}

// Classify returns a set of semantic tags for a file based on its path and MIME type.
func Classify(relPath, mime string, info fs.FileInfo) []string {
	var tags []string
	ext := strings.ToLower(filepath.Ext(relPath))
	base := strings.ToLower(filepath.Base(relPath))
	dir := strings.ToLower(filepath.Dir(relPath))

	// Archive detection
	if isArchiveExt(ext) {
		tags = append(tags, "archive")
	}

	// Source map
	if strings.HasSuffix(relPath, ".map") {
		tags = append(tags, "debug", "sourcemap")
	}

	// Debug symbols
	if ext == ".pdb" || ext == ".dsym" || strings.Contains(relPath, ".dSYM/") {
		tags = append(tags, "debug")
	}

	// Frontend bundles
	if ext == ".js" || ext == ".mjs" || ext == ".css" || ext == ".html" {
		tags = append(tags, "frontend")
	}

	// Config / env files
	if base == ".env" || strings.HasPrefix(base, ".env.") || ext == ".env" {
		tags = append(tags, "config", "sensitive")
	}

	// Test files
	if strings.Contains(dir, "test") || strings.Contains(dir, "spec") ||
		strings.Contains(base, "_test") || strings.Contains(base, ".test.") ||
		strings.Contains(base, ".spec.") {
		tags = append(tags, "test")
	}

	// Vendor
	if strings.Contains(dir, "vendor") || strings.Contains(dir, "node_modules") {
		tags = append(tags, "vendor")
	}

	// Git remnants
	if strings.HasPrefix(relPath, ".git/") || dir == ".git" {
		tags = append(tags, "vcs")
	}

	// Binary detection via MIME
	if strings.HasPrefix(mime, "application/") &&
		!strings.Contains(mime, "json") &&
		!strings.Contains(mime, "xml") &&
		!strings.Contains(mime, "javascript") {
		tags = append(tags, "binary")
	}

	// Script files
	if ext == ".sh" || ext == ".bash" || ext == ".py" || ext == ".rb" {
		tags = append(tags, "script")
	}

	return tags
}

func isArchiveExt(ext string) bool {
	switch ext {
	case ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz",
		".jar", ".war", ".ear", ".whl", ".nupkg",
		".deb", ".rpm", ".dmg", ".appimage":
		return true
	}
	return false
}
