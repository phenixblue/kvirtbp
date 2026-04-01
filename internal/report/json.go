package report

import (
	"encoding/json"
	"io"

	"github.com/phenixblue/kvirtbp/internal/checks"
)

func WriteJSON(out io.Writer, result checks.RunResult) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
