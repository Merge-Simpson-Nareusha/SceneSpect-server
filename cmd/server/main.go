package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	authhandler "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/handler"
	authrepository "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/repository"
	authservice "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/service"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/config"
	postgresdb "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/database/postgres"
	redisdb "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/database/redis"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/mailer"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// # 인증 서버 시작 기능
func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	postgres, err := postgresdb.NewPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer postgres.Close()

	redisClient, err := redisdb.NewRedis(ctx, cfg.RedisURL)
	if err != nil {
		log.Fatal(err)
	}
	defer redisClient.Close()

	sender := buildMailSender(cfg)
	tokenManager := security.TokenManager{Key: cfg.JWTKey, Issuer: cfg.Issuer, Audience: cfg.Audience, TTL: cfg.AccessTTL}
	authRepository := authrepository.NewPostgresAuthRepository(postgres)
	authService := authservice.NewAuthService(authRepository, redisdb.Ephemeral{Client: redisClient}, sender, tokenManager, cfg.CodeKey, cfg.BcryptCost, cfg.RefreshTTL)
	authHandler := authhandler.NewHandler(authService, cfg)
	server := newHTTPServer(cfg.Address, newRouter(authHandler))

	go serve(server, stop)
	<-ctx.Done()

	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownContext)
}

// # 이메일 발송기 구성 기능
func buildMailSender(cfg config.Config) mailer.Sender {
	if cfg.Environment == "development" && cfg.SMTPHost == "console" {
		return mailer.Console{Logger: log.Default()}
	}
	return mailer.SMTP{
		Host:          cfg.SMTPHost,
		Port:          cfg.SMTPPort,
		User:          cfg.SMTPUser,
		Password:      cfg.SMTPPassword,
		From:          cfg.MailFrom,
		AllowInsecure: cfg.SMTPInsecure,
	}
}
