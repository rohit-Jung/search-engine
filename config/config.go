// Package Config
package config

import (
	"strings"

	"github.com/go-playground/validator/v10"
	_ "github.com/joho/godotenv/autoload"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/v2"
)

type Config struct {
	Nvd      NvdConfig      `koanf:"nvd" validate:"required"`
	Database DatabaseConfig `koanf:"database" validate:"required"`
}

type DatabaseConfig struct{}

type NvdConfig struct {
	APIKey string `koanf:"api_key" validate:"required"`
}

var envPrefix = "SEARCH_ENGINE_"

func LoadConfig() (*Config, error) {
	k := koanf.New(".")

	err := k.Load(env.Provider(envPrefix, ".", func(s string) string {
		return strings.ToLower(strings.TrimPrefix(s, envPrefix))
	}), nil)
	if err != nil {
		return nil, err
	}

	mainConfig := &Config{}
	err = k.Unmarshal("", mainConfig)
	if err != nil {
		return nil, err
	}

	v := validator.New()
	if err := v.Struct(mainConfig); err != nil {
		return nil, err
	}

	return mainConfig, nil
}
