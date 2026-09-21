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

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/user"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/config"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/database"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/mailer"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/middleware"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
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

	redisClient, err := database.NewRedis(ctx, cfg.RedisURL)
	if err != nil {
		log.Fatal(err)
	}
	defer redisClient.Close()

	// 의존성 조립 순서를 한 곳에 모아 전역 설정·DB와 도메인 흐름을 쉽게 추적합니다.
	sender := buildMailSender(cfg)
	tokenManager := security.TokenManager{Key: cfg.JWTKey, Issuer: cfg.Issuer, Audience: cfg.Audience, TTL: cfg.AccessTTL}
	authRepository := auth.NewPostgresAuthRepository(postgres)
	authService := auth.NewAuthService(authRepository, database.Ephemeral{Client: redisClient}, sender, tokenManager, cfg.CodeKey, cfg.BcryptCost, cfg.RefreshTTL)
	authHandler := auth.NewHandler(authService, cfg)
	userHandler := user.NewHandler(authService)
	server := newHTTPServer(cfg.Address, newRouter(authHandler, userHandler))

	go serve(server, stop)
	<-ctx.Done()

	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownContext)
}

func newRouter(authHandler *auth.AuthHandler, userHandler *user.Handler) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery(), authHandler.CORS())
	r.GET("/healthz", authHandler.Health)

	api := r.Group("/api/v1")
	authRoutes := api.Group("/auth")
	authRoutes.GET("/signup/terms", authHandler.SignupTerms)
	authRoutes.POST("/signup/start", authHandler.SignupStart)
	authRoutes.POST("/signup/password", authHandler.SignupPassword)
	authRoutes.POST("/signup/email/send", authHandler.SignupEmailSend)
	authRoutes.POST("/signup/email/verify", authHandler.SignupEmailVerify)
	authRoutes.POST("/signup/terms", authHandler.SignupComplete)
	authRoutes.POST("/login", authHandler.Login)
	authRoutes.POST("/token/refresh", authHandler.Refresh)
	authRoutes.POST("/logout", authHandler.Logout)
	authRoutes.POST("/password/forgot", authHandler.PasswordForgot)
	authRoutes.POST("/password/reset", authHandler.PasswordReset)
	authRoutes.POST("/account/find", authHandler.AccountFind)

	protected := api.Group("")
	protected.Use(middleware.Authenticate(authHandler.Authenticator()))
	protected.GET("/me", userHandler.Me)
	protected.PATCH("/me/nickname", userHandler.UpdateNickname)

	admin := api.Group("/admin")
	admin.Use(middleware.Authenticate(authHandler.Authenticator()), middleware.RequireRole("ADMIN"))
	admin.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "scope": "admin"})
	})
	return r
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
