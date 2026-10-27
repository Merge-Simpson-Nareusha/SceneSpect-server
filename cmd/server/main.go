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
	mediahandler "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/media/handler"
	projecthandler "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/project/handler"
	projectrepository "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/project/repository"
	projectservice "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/project/service"
	teamhandler "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/team/handler"
	teamrepository "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/team/repository"
	teamservice "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/team/service"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/config"
	postgresdb "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/database/postgres"
	redisdb "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/database/redis"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/mailer"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/media"
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
	ephemeral := redisdb.Ephemeral{Client: redisClient}
	authService := authservice.NewAuthService(authRepository, ephemeral, sender, tokenManager, cfg.CodeKey, cfg.BcryptCost, cfg.RefreshTTL)
	oauthService := authservice.NewOAuthService(authRepository, ephemeral, authService, tokenManager, cfg.RefreshTTL, cfg)
	authHandler := authhandler.NewHandlerWithOAuth(authService, oauthService, cfg)
	teamHandler := teamhandler.NewTeamHandler(teamservice.NewTeamService(teamrepository.NewPostgresRepository(postgres)))
	projectHandler := projecthandler.NewProjectHandler(projectservice.NewProjectService(projectrepository.NewPostgresRepository(postgres)))
	mediaStore, err := media.NewStore(cfg.MediaStorageDir, cfg.MediaMaxImageBytes)
	if err != nil {
		log.Fatal(err)
	}
	mediaHandler := mediahandler.NewHandler(mediaStore)
	server := newHTTPServer(cfg.Address, newRouter(authHandler, teamHandler, projectHandler, mediaHandler))

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
