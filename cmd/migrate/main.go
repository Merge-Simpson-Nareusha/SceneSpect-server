package main

import (
	"context"
	"log"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/config"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/migrations"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	if err = migrations.Up(context.Background(), cfg.DatabaseURL); err != nil {
		log.Fatal(err)
	}
}
