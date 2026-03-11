package model

import "time"

// DRMStubType identifies the kind of runtime stub injected.
type DRMStubType string

const (
	StubIntegrityCheck DRMStubType = "integrity_check"
	StubAntiDebug      DRMStubType = "anti_debug"
	StubLicense        DRMStubType = "license"
	StubTamperDetect   DRMStubType = "tamper_detect"
)

// OnTamperAction is the action to take when tamper is detected.
type OnTamperAction string

const (
	OnTamperExit     OnTamperAction = "exit"
	OnTamperLog      OnTamperAction = "log"
	OnTamperCallback OnTamperAction = "callback"
)

// DRMStub describes a single runtime protection stub that was injected.
type DRMStub struct {
	Type        DRMStubType    `json:"type"`
	Target      string         `json:"target"`      // file path the stub was injected into
	Language    string         `json:"language"`    // js, go, dotnet, python, jvm
	OnTamper    OnTamperAction `json:"on_tamper,omitempty"`
	ExpectedHash string        `json:"expected_hash,omitempty"`
	InjectedAt  time.Time      `json:"injected_at"`
}

// DRMManifest records all DRM stubs injected into an artifact.
type DRMManifest struct {
	GeneratedAt time.Time `json:"generated_at"`
	InputPath   string    `json:"input_path"`
	Stubs       []DRMStub `json:"stubs"`
}
