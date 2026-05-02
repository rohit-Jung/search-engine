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
	Nvd      NvdConfig      `koanf:"nvd"`
	Database DatabaseConfig `koanf:"database"`
}

type DatabaseConfig struct {
	Host     string `koanf:"host" validate:"required"`
	Port     int    `koanf:"port" validate:"required"`
	User     string `koanf:"user" validate:"required"`
	Password string `koanf:"password"`
	Name     string `koanf:"name" validate:"required"`
}

type NvdConfig struct {
	APIKey string `koanf:"api_key"`
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

	applyDefaults(mainConfig)

	v := validator.New()
	if err := v.Struct(mainConfig); err != nil {
		return nil, err
	}

	return mainConfig, nil
}

func applyDefaults(cfg *Config) {
	// Defaults are chosen to match docker-compose.yml provided in this repo.
	if cfg.Database.Host == "" {
		cfg.Database.Host = "localhost"
	}
	if cfg.Database.Port == 0 {
		cfg.Database.Port = 5432
	}
	if cfg.Database.User == "" {
		cfg.Database.User = "postgres"
	}
	if cfg.Database.Password == "" {
		cfg.Database.Password = "postgres"
	}
	if cfg.Database.Name == "" {
		cfg.Database.Name = "search_engine"
	}
}
