package model

// TransformAction describes what kind of mutation was performed.
type TransformAction string

const (
	ActionDelete  TransformAction = "delete"
	ActionRedact  TransformAction = "redact"
	ActionRewrite TransformAction = "rewrite"
	ActionAdd     TransformAction = "add"
	ActionRename  TransformAction = "rename"
)

// Transform records a single mutation applied to the artifact tree.
type Transform struct {
	ID        string          `json:"id"`
	Action    TransformAction `json:"action"`
	Path      string          `json:"path"`
	Reason    string          `json:"reason"`
	BeforeSHA string          `json:"before_sha256"`
	AfterSHA  *string         `json:"after_sha256"`
	Staged    bool            `json:"staged,omitempty"` // true if dry-run
}
