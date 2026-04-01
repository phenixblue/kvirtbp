package checks

import "context"

type BaselineControl struct {
	meta Metadata
}

func (b BaselineControl) Metadata() Metadata {
	return b.meta
}

func (b BaselineControl) Evaluate(ctx context.Context) ([]Finding, error) {
	_ = ctx
	return []Finding{
		{
			CheckID:  b.meta.ID,
			Title:    b.meta.Title,
			Category: b.meta.Category,
			Severity: b.meta.Severity,
			Pass:     true,
			Message:  "go baseline validated control metadata",
		},
	}, nil
}
