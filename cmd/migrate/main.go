package main

import (
	"context"
	"log"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/config"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/migrations"
)

// # 데이터베이스 마이그레이션 실행 기능
func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	if err = migrations.Up(context.Background(), cfg.DatabaseURL); err != nil {
		log.Fatal(err)
	}
}
