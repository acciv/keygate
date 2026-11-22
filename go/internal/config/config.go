package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Addr             string
	MasterKey        string
	AllowedProviders string
	AllowedScopes    string
	MaxTTL           int
	DenyUnknown      bool
	RatePerMinute    int
	Providers        map[string]string
}

func Load(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	cfg := &Config{
		Addr:             ":8080",
		MasterKey:        "kg_master_change_me",
		AllowedProviders: "telegram,openai",
		AllowedScopes:    "read",
		MaxTTL:           300,
		DenyUnknown:      true,
		RatePerMinute:    60,
		Providers:        make(map[string]string),
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		switch key {
		case "addr":
			cfg.Addr = value
		case "master_key":
			cfg.MasterKey = value
		case "allowed_providers":
			cfg.AllowedProviders = value
		case "allowed_scopes":
			cfg.AllowedScopes = value
		case "max_ttl":
			if n, err := strconv.Atoi(value); err == nil {
				cfg.MaxTTL = n
			}
		case "deny_unknown":
			cfg.DenyUnknown = strings.EqualFold(value, "true") || value == "1"
		case "rate_per_minute":
			if n, err := strconv.Atoi(value); err == nil {
				cfg.RatePerMinute = n
			}
		default:
			if strings.HasPrefix(key, "provider.") {
				cfg.Providers[strings.TrimPrefix(key, "provider.")] = value
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) PolicyJSON() string {
	return fmt.Sprintf(
		`{"allowed_providers":%q,"allowed_scopes":%q,"max_ttl":%d,"deny_unknown":%t}`,
		c.AllowedProviders, c.AllowedScopes, c.MaxTTL, c.DenyUnknown,
	)
}
