package main

import (
	"log"
	"os"
	"time"

	"triggerd/internal/config"
	"triggerd/internal/rules"
	"triggerd/internal/triggers"
)

func main() {
	configPath := "./rules.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	actions.RegisterBuiltins()
	triggers.RegisterBuiltins()

	log.Println("Triggerd starting...")

	go rules.RunEngine(cfg)

	// Block forever
	select {}
}
