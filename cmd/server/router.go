package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/docs"
	authhandler "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/handler"
	authorizationmiddleware "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/authorization/middleware"
	authorizationmodel "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/authorization/model"
	mediahandler "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/media/handler"
	projecthandler "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/project/handler"
	teamhandler "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/team/handler"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/middleware"
)

// # HTTP 라우터 구성 기능
func newRouter(authHandler *authhandler.AuthHandler, teamHandler *teamhandler.TeamHandler, projectHandler *projecthandler.ProjectHandler, mediaHandler *mediahandler.Handler) *gin.Engine {
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
	authRequired := middleware.Authenticate(authHandler.Authenticator())
	authRoutes.GET("/me", authRequired, authHandler.Me)
	authRoutes.PATCH("/me/nickname", authRequired, authHandler.NicknameUpdate)
	authRoutes.PATCH("/me/profile", authRequired, authHandler.ProfileUpdate)
	authRoutes.PATCH("/me/display-theme", authRequired, authHandler.DisplayThemeUpdate)
	authRoutes.POST("/me/password", authRequired, authHandler.PasswordChange)
	authRoutes.GET("/oauth/:provider/start", authHandler.OAuthStart)
	authRoutes.GET("/oauth/:provider/callback", authHandler.OAuthCallback)
	authRoutes.POST("/oauth/apple/callback", authHandler.OAuthCallback)
	authRoutes.POST("/oauth/:provider/link/start", authRequired, authHandler.OAuthLinkStart)
	authRoutes.POST("/oauth/complete/email/send", authHandler.OAuthEmailSend)
	authRoutes.POST("/oauth/complete/email/verify", authHandler.OAuthEmailVerify)
	authRoutes.POST("/oauth/complete", authHandler.OAuthComplete)

	teamHandler.Register(api, authRequired)
	projectHandler.Register(api, authRequired)
	mediaHandler.Register(r, api, authRequired)
	docs.RegisterRoutes(r)

	admin := api.Group("/admin")
	// 인증(Authentication)을 먼저 통과한 뒤 인가(Authorization) 정책을 적용합니다.
	admin.Use(middleware.Authenticate(authHandler.Authenticator()), authorizationmiddleware.RequireRole(authorizationmodel.AdminRole))
	admin.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "scope": "admin"})
	})
	return r
}
