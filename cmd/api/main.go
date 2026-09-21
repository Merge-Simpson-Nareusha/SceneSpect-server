package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/cache"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/config"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/database"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/handler"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/mailer"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/repository"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/router"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/security"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/service"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	postgres, err := database.NewPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer postgres.Close()

	redisOptions, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Fatal(err)
	}
	redisClient := redis.NewClient(redisOptions)
	defer redisClient.Close()
	if err = redisClient.Ping(ctx).Err(); err != nil {
		log.Fatal(err)
	}

	// FirstServer식으로 연결 순서와 책임을 한 곳에서 읽을 수 있게 조립합니다.
	// database/cache -> repository -> service -> handler -> router 순서입니다.
	sender := buildMailSender(cfg)
	tokenManager := security.TokenManager{Key: cfg.JWTKey, Issuer: cfg.Issuer, Audience: cfg.Audience, TTL: cfg.AccessTTL}
	authRepository := repository.NewPostgresAuthRepository(postgres)
	authService := service.NewAuthService(authRepository, cache.Ephemeral{Client: redisClient}, sender, tokenManager, cfg.CodeKey, cfg.BcryptCost, cfg.RefreshTTL)
	authHandler := handler.NewAuthHandler(authService, cfg)
	server := newHTTPServer(cfg.Address, router.New(authHandler))

	go serve(server, stop)
	<-ctx.Done()

	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownContext)
}

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

func newHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func serve(server *http.Server, stop context.CancelFunc) {
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("server: %v", err)
		stop()
	}
}
