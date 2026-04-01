package checks

import (
	"fmt"
	"strings"
)

type Filter struct {
	IncludeIDs []string
	ExcludeIDs []string
	Categories []string
	Severities []Severity
}

func ParseSeverities(values []string) ([]Severity, error) {
	if len(values) == 0 {
		return nil, nil
	}

	result := make([]Severity, 0, len(values))
	for _, v := range values {
		s, err := ParseSeverity(v)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, nil
}

func ParseSeverity(v string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "info":
		return SeverityInfo, nil
	case "warning", "warn":
		return SeverityWarning, nil
	case "error":
		return SeverityError, nil
	default:
		return "", fmt.Errorf("unsupported severity: %s", v)
	}
}

func FilterRegistry(registry []Check, filter Filter) []Check {
	include := toSet(filter.IncludeIDs)
	exclude := toSet(filter.ExcludeIDs)
	categories := toSet(filter.Categories)
	severities := toSeveritySet(filter.Severities)

	filtered := make([]Check, 0, len(registry))
	for _, c := range registry {
		m := c.Metadata()
		id := strings.ToLower(m.ID)
		if len(include) > 0 {
			if _, ok := include[id]; !ok {
				continue
			}
		}
		if _, excluded := exclude[id]; excluded {
			continue
		}
		if len(categories) > 0 {
			if _, ok := categories[strings.ToLower(m.Category)]; !ok {
				continue
			}
		}
		if len(severities) > 0 {
			if _, ok := severities[m.Severity]; !ok {
				continue
			}
		}

		filtered = append(filtered, c)
	}

	return filtered
}

func FilterFindings(findings []Finding, filter Filter) []Finding {
	include := toSet(filter.IncludeIDs)
	exclude := toSet(filter.ExcludeIDs)
	categories := toSet(filter.Categories)
	severities := toSeveritySet(filter.Severities)

	filtered := make([]Finding, 0, len(findings))
	for _, f := range findings {
		id := strings.ToLower(f.CheckID)
		if len(include) > 0 {
			if _, ok := include[id]; !ok {
				continue
			}
		}
		if _, excluded := exclude[id]; excluded {
			continue
		}
		if len(categories) > 0 {
			if _, ok := categories[strings.ToLower(f.Category)]; !ok {
				continue
			}
		}
		if len(severities) > 0 {
			if _, ok := severities[f.Severity]; !ok {
				continue
			}
		}

		filtered = append(filtered, f)
	}

	return filtered
}

func toSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		n := strings.ToLower(strings.TrimSpace(v))
		if n == "" {
			continue
		}
		set[n] = struct{}{}
	}
	return set
}

func toSeveritySet(values []Severity) map[Severity]struct{} {
	if len(values) == 0 {
		return nil
	}
	set := make(map[Severity]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	return set
}
