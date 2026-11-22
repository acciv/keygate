package main

import (
	"flag"
	"log"

	"github.com/acciv/keygate/internal/config"
	"github.com/acciv/keygate/internal/server"
)

func main() {
	configPath := flag.String("config", "../config/keygate.conf", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := server.New(cfg).ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}
