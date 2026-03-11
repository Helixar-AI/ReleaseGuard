package policy

import (
	"time"

	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// Evaluator runs policy gates against a set of findings.
type Evaluator struct {
	cfg *config.Config
}

// NewEvaluator returns an Evaluator configured from cfg.
func NewEvaluator(cfg *config.Config) *Evaluator {
	return &Evaluator{cfg: cfg}
}

// Evaluate assesses findings against all configured policy gates.
func (e *Evaluator) Evaluate(findings []model.Finding) *model.PolicyResult {
	result := &model.PolicyResult{
		Result:    model.OutcomePass,
		Timestamp: time.Now().UTC(),
	}

	// Severity and category gates (fail_on)
	for _, gate := range e.cfg.Policy.FailOn {
		gr := e.evalGate(gate, findings, model.OutcomeFail)
		result.Gates = append(result.Gates, gr)
		if gr.Result == model.OutcomeFail {
			result.Result = model.OutcomeFail
		}
	}

	// Warn gates
	for _, gate := range e.cfg.Policy.WarnOn {
		gr := e.evalGate(gate, findings, model.OutcomeWarn)
		result.Gates = append(result.Gates, gr)
		if gr.Result == model.OutcomeWarn && result.Result == model.OutcomePass {
			result.Result = model.OutcomeWarn
		}
	}

	return result
}

func (e *Evaluator) evalGate(gate config.PolicyGate, findings []model.Finding, failWith model.PolicyOutcome) model.GateResult {
	var matched []string

	for _, f := range findings {
		if gate.Severity != "" && f.Severity == gate.Severity {
			matched = append(matched, f.ID)
		}
		if gate.Category != "" && f.Category == gate.Category {
			matched = append(matched, f.ID)
		}
	}

	ruleName := gate.Severity
	if gate.Category != "" {
		ruleName = "category:" + gate.Category
	}

	if len(matched) > 0 {
		return model.GateResult{
			Rule:     ruleName,
			Result:   failWith,
			Findings: matched,
		}
	}
	return model.GateResult{
		Rule:   ruleName,
		Result: model.OutcomePass,
	}
}
