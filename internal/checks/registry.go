package checks

import "context"

type Check interface {
	Metadata() Metadata
	Evaluate(ctx context.Context) ([]Finding, error)
}

func DefaultChecks() []Check {
	defs := DefaultControlCatalog()
	registry := make([]Check, 0, len(defs))
	for _, d := range defs {
		registry = append(registry, BaselineControl{meta: d})
	}
	return registry
}

func RunAll(ctx context.Context, registry []Check) (RunResult, error) {
	return RunFiltered(ctx, registry, Filter{})
}

func RunFiltered(ctx context.Context, registry []Check, filter Filter) (RunResult, error) {
	result := RunResult{
		SchemaVersion: ReportSchemaVersion,
		Findings:      make([]Finding, 0),
	}

	selected := FilterRegistry(registry, filter)
	for _, c := range selected {
		findings, err := c.Evaluate(ctx)
		if err != nil {
			return RunResult{}, err
		}
		result.Findings = append(result.Findings, findings...)
	}
	result.Summary = Summarize(result.Findings)
	return result, nil
}
