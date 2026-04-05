package collector

// MergeAll merges an arbitrary number of CollectorConfig slices left-to-right.
// Later slices win on name collision. The result is equivalent to folding
// MergeCollectorConfigs over the sources in order.
func MergeAll(sources ...[]CollectorConfig) []CollectorConfig {
	result := []CollectorConfig{}
	for _, s := range sources {
		result = MergeCollectorConfigs(result, s)
	}
	return result
}

// MergeCollectorConfigs returns a deduplicated union of a and b.
// When both slices contain a config with the same Name, b's entry wins.
// Order is preserved: all entries from a appear first (unless replaced by b),
// then any entries from b whose names were not in a.
func MergeCollectorConfigs(a, b []CollectorConfig) []CollectorConfig {
	bIndex := make(map[string]CollectorConfig, len(b))
	for _, cfg := range b {
		bIndex[cfg.Name] = cfg
	}

	result := make([]CollectorConfig, 0, len(a)+len(b))
	seen := make(map[string]struct{}, len(a))

	for _, cfg := range a {
		if override, ok := bIndex[cfg.Name]; ok {
			result = append(result, override)
		} else {
			result = append(result, cfg)
		}
		seen[cfg.Name] = struct{}{}
	}

	for _, cfg := range b {
		if _, already := seen[cfg.Name]; !already {
			result = append(result, cfg)
		}
	}

	return result
}
