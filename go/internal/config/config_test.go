package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keygate.conf")
	content := "addr=:9090\nmaster_key=secret\nmax_ttl=120\ndeny_unknown=false\nprovider.telegram=fake\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":9090" || cfg.MasterKey != "secret" || cfg.MaxTTL != 120 || cfg.DenyUnknown {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.Providers["telegram"] != "fake" {
		t.Fatalf("provider missing: %+v", cfg.Providers)
	}
}
