package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Output      string
	Timeout     time.Duration
	Concurrency int
}

func Load() (Config, error) {
	v := viper.New()
	v.SetEnvPrefix("KVIRTBP")
	v.AutomaticEnv()

	v.SetDefault("output", "table")
	v.SetDefault("timeout", "30s")
	v.SetDefault("concurrency", 4)

	timeout, err := time.ParseDuration(v.GetString("timeout"))
	if err != nil {
		return Config{}, err
	}

	return Config{
		Output:      v.GetString("output"),
		Timeout:     timeout,
		Concurrency: v.GetInt("concurrency"),
	}, nil
}
