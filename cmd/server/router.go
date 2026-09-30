package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	authhandler "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/handler"
	authorizationmiddleware "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/authorization/middleware"
	authorizationmodel "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/authorization/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/middleware"
)

// newRouter는 API 경로와 middleware 실행 순서를 선언합니다.
// 입력 검증·업무 정책·저장 쿼리는 이곳에 두지 않고 도메인 계층에 위임합니다.
func newRouter(authHandler *authhandler.AuthHandler) *gin.Engine {
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

	admin := api.Group("/admin")
	// 인증(Authentication)을 먼저 통과한 뒤 인가(Authorization) 정책을 적용합니다.
	admin.Use(middleware.Authenticate(authHandler.Authenticator()), authorizationmiddleware.RequireRole(authorizationmodel.AdminRole))
	admin.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "scope": "admin"})
	})
	return r
}
