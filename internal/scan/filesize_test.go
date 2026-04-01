package scan

import (
	"testing"

	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

func TestFileSizeScanner_Name(t *testing.T) {
	s := &FileSizeScanner{}
	if s.Name() != "filesize" {
		t.Errorf("Name() = %q, want %q", s.Name(), "filesize")
	}
}

func TestFileSizeScanner_Scan(t *testing.T) {
	const (
		kb  = int64(1024)
		mb  = 1024 * kb
		mib = mb
	)

	makeCfg := func(maxFile, maxTotal int64, perExt map[string]int64) *config.Config {
		cfg := config.DefaultConfig()
		cfg.Scanning.FileSize = config.FileSizeConfig{
			Enabled:       true,
			MaxFileBytes:  maxFile,
			MaxTotalBytes: maxTotal,
			PerExtension:  perExt,
		}
		return cfg
	}

	makeArtifacts := func(sizes ...int64) []model.Artifact {
		arts := make([]model.Artifact, 0, len(sizes))
		for i, sz := range sizes {
			arts = append(arts, model.Artifact{
				Path: "file.bin",
				Size: sz,
				Kind: "file",
			})
			_ = i
		}
		return arts
	}

	t.Run("file under threshold produces no finding", func(t *testing.T) {
		cfg := makeCfg(10*mib, 100*mib, nil)
		arts := makeArtifacts(5 * mib)
		s := &FileSizeScanner{}
		findings, err := s.Scan(".", arts, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})

	t.Run("file at exact threshold produces no finding", func(t *testing.T) {
		cfg := makeCfg(10*mib, 100*mib, nil)
		arts := makeArtifacts(10 * mib)
		s := &FileSizeScanner{}
		findings, err := s.Scan(".", arts, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("expected 0 findings at threshold, got %d", len(findings))
		}
	})

	t.Run("file over threshold produces RG-SIZE-001", func(t *testing.T) {
		cfg := makeCfg(10*mib, 100*mib, nil)
		arts := makeArtifacts(11 * mib)
		s := &FileSizeScanner{}
		findings, err := s.Scan(".", arts, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].ID != "RG-SIZE-001" {
			t.Errorf("expected ID RG-SIZE-001, got %q", findings[0].ID)
		}
		if findings[0].Category != model.CategoryFileSize {
			t.Errorf("expected category %q, got %q", model.CategoryFileSize, findings[0].Category)
		}
		if findings[0].Severity != model.SeverityMedium {
			t.Errorf("expected severity %q, got %q", model.SeverityMedium, findings[0].Severity)
		}
	})

	t.Run("per-extension override allows larger file", func(t *testing.T) {
		cfg := makeCfg(1*mib, 100*mib, map[string]int64{".wasm": 50 * mib})
		arts := []model.Artifact{
			{Path: "app.wasm", Size: 20 * mib, Kind: "file"},
		}
		s := &FileSizeScanner{}
		findings, err := s.Scan(".", arts, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("expected 0 findings for .wasm within override limit, got %d", len(findings))
		}
	})

	t.Run("per-extension override triggers when exceeded", func(t *testing.T) {
		cfg := makeCfg(100*mib, 1000*mib, map[string]int64{".wasm": 5 * mib})
		arts := []model.Artifact{
			{Path: "app.wasm", Size: 10 * mib, Kind: "file"},
		}
		s := &FileSizeScanner{}
		findings, err := s.Scan(".", arts, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 1 || findings[0].ID != "RG-SIZE-001" {
			t.Errorf("expected RG-SIZE-001 for oversized .wasm, got %+v", findings)
		}
	})

	t.Run("total bundle over threshold produces RG-SIZE-002", func(t *testing.T) {
		cfg := makeCfg(100*mib, 10*mib, nil)
		arts := makeArtifacts(6*mib, 6*mib) // 12 MiB total > 10 MiB limit
		s := &FileSizeScanner{}
		findings, err := s.Scan(".", arts, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var found bool
		for _, f := range findings {
			if f.ID == "RG-SIZE-002" {
				found = true
				if f.Severity != model.SeverityHigh {
					t.Errorf("RG-SIZE-002 expected severity %q, got %q", model.SeverityHigh, f.Severity)
				}
				break
			}
		}
		if !found {
			t.Errorf("expected RG-SIZE-002 finding, got: %+v", findings)
		}
	})

	t.Run("directories are skipped in size accounting", func(t *testing.T) {
		cfg := makeCfg(1*kb, 1*kb, nil)
		arts := []model.Artifact{
			{Path: "subdir", Size: 999999, Kind: "dir"},
		}
		s := &FileSizeScanner{}
		findings, err := s.Scan(".", arts, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("expected directories to be skipped, got %d findings", len(findings))
		}
	})

	t.Run("zero-byte file produces no finding", func(t *testing.T) {
		cfg := makeCfg(10*mib, 100*mib, nil)
		arts := makeArtifacts(0)
		s := &FileSizeScanner{}
		findings, err := s.Scan(".", arts, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("expected 0 findings for zero-byte file, got %d", len(findings))
		}
	})
}

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1024 * 1024, "1.0 MiB"},
		{10 * 1024 * 1024, "10.0 MiB"},
	}

	for _, tc := range tests {
		got := humanBytes(tc.input)
		if got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
