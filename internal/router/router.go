// Package router assembles the HTTP routes and middleware for the API.
package router

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/handler"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/middleware"
)

func New(authHandler *handler.AuthHandler) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery(), authHandler.CORS())
	r.GET("/healthz", authHandler.Health)

	api := r.Group("/api/v1")
	auth := api.Group("/auth")
	auth.GET("/signup/terms", authHandler.SignupTerms)
	auth.POST("/signup/start", authHandler.SignupStart)
	auth.POST("/signup/password", authHandler.SignupPassword)
	auth.POST("/signup/email/send", authHandler.SignupEmailSend)
	auth.POST("/signup/email/verify", authHandler.SignupEmailVerify)
	auth.POST("/signup/terms", authHandler.SignupComplete)
	auth.POST("/login", authHandler.Login)
	auth.POST("/token/refresh", authHandler.Refresh)
	auth.POST("/logout", authHandler.Logout)
	auth.POST("/password/forgot", authHandler.PasswordForgot)
	auth.POST("/password/reset", authHandler.PasswordReset)
	auth.POST("/account/find", authHandler.AccountFind)

	protected := api.Group("")
	protected.Use(middleware.Authenticate(authHandler.Authenticator()))
	protected.GET("/me", authHandler.Me)
	protected.PATCH("/me/nickname", authHandler.UpdateNickname)

	admin := api.Group("/admin")
	admin.Use(middleware.Authenticate(authHandler.Authenticator()), middleware.RequireRole("ADMIN"))
	admin.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "scope": "admin"})
	})
	return r
}
