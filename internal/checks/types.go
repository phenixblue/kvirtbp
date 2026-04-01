package checks

type Severity string

type Impact string

type Confidence string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

const (
	ImpactLow    Impact = "low"
	ImpactMedium Impact = "medium"
	ImpactHigh   Impact = "high"
)

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type Metadata struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Category string   `json:"category"`
	Severity Severity `json:"severity"`
}

type Finding struct {
	CheckID             string            `json:"checkId"`
	Title               string            `json:"title"`
	Category            string            `json:"category"`
	Severity            Severity          `json:"severity"`
	Impact              Impact            `json:"impact,omitempty"`
	Confidence          Confidence        `json:"confidence,omitempty"`
	Pass                bool              `json:"pass"`
	Waived              bool              `json:"waived,omitempty"`
	WaiverJustification string            `json:"waiverJustification,omitempty"`
	WaiverOwner         string            `json:"waiverOwner,omitempty"`
	WaiverExpires       string            `json:"waiverExpires,omitempty"`
	ReasonCode          string            `json:"reasonCode,omitempty"`
	Message             string            `json:"message"`
	ResourceRef         string            `json:"resourceRef,omitempty"`
	Evidence            map[string]string `json:"evidence,omitempty"`
	RemediationID       string            `json:"remediationId,omitempty"`
	Remediation         string            `json:"remediation,omitempty"`
}

type Summary struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Waived  int `json:"waived"`
	Info    int `json:"info"`
	Warning int `json:"warning"`
	Error   int `json:"error"`
}

type RunResult struct {
	SchemaVersion string       `json:"schemaVersion"`
	Metadata      *MetadataRun `json:"metadata,omitempty"`
	Summary       Summary      `json:"summary"`
	Findings      []Finding    `json:"findings"`
}

type MetadataRun struct {
	Engine                    string   `json:"engine,omitempty"`
	NamespaceInclude          []string `json:"namespaceInclude,omitempty"`
	NamespaceExclude          []string `json:"namespaceExclude,omitempty"`
	ClusterContextHash        string   `json:"clusterContextHash,omitempty"`
	ClusterContextHashVersion string   `json:"clusterContextHashVersion,omitempty"`
	DurationMillis            int64    `json:"durationMillis,omitempty"`
	PolicyFile                string   `json:"policyFile,omitempty"`
	PolicyBundle              string   `json:"policyBundle,omitempty"`
	WaiverFile                string   `json:"waiverFile,omitempty"`
	EvaluationMode            string   `json:"evaluationMode,omitempty"`
	KubeContext               string   `json:"kubeContext,omitempty"`
	KubeconfigProvided        bool     `json:"kubeconfigProvided,omitempty"`
}

const ReportSchemaVersion = "v1alpha1"

const (
	ExitCodeSuccess   = 0
	ExitCodeViolation = 2
	ExitCodePartial   = 3
)

func Summarize(findings []Finding) Summary {
	s := Summary{Total: len(findings)}
	for _, f := range findings {
		if f.Waived {
			s.Waived++
		} else if f.Pass {
			s.Passed++
		} else {
			s.Failed++
		}

		switch f.Severity {
		case SeverityInfo:
			s.Info++
		case SeverityWarning:
			s.Warning++
		case SeverityError:
			s.Error++
		}
	}
	return s
}

func ExitCode(result RunResult) int {
	hasPartial := false
	hasViolation := false

	for _, f := range result.Findings {
		if f.Pass || f.Waived {
			continue
		}
		hasViolation = true
		if f.CheckID == "cluster-connectivity" || f.CheckID == "cluster-discovery" {
			hasPartial = true
		}
	}

	if hasPartial {
		return ExitCodePartial
	}
	if hasViolation {
		return ExitCodeViolation
	}
	return ExitCodeSuccess
}
