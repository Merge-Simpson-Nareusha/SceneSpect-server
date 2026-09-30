package main

import (
	"context"
	"log"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/config"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/migrations"
)

// main은 환경 설정을 읽고 내장된 DB migration을 적용합니다.
func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	if err = migrations.Up(context.Background(), cfg.DatabaseURL); err != nil {
		log.Fatal(err)
	}
}
