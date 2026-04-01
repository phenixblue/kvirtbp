package eval

import (
	"context"

	"github.com/phenixblue/kvirtbp/internal/checks"
)

type RunRequest struct {
	Registry     []checks.Check
	Filter       checks.Filter
	PolicyFile   string
	PolicyBundle string
}

type Evaluator interface {
	Evaluate(ctx context.Context, req RunRequest) (checks.RunResult, error)
	Name() string
}
