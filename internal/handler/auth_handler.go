// Package handler translates HTTP requests into authentication use cases.
package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/config"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/service"
)

const refreshCookie = "scenespect_refresh"

// AuthService is the transport-facing use-case boundary.
type AuthService interface {
	Terms(context.Context) ([]domain.Term, error)
	StartSignup(context.Context, string, string) (service.SignupStartResult, error)
	SetSignupPassword(context.Context, string, string, string) error
	SendSignupCode(context.Context, string, string) (service.VerificationResult, error)
	VerifySignupCode(context.Context, string, string) error
	CompleteSignup(context.Context, string, []domain.Consent) (domain.Tokens, error)
	Login(context.Context, string, string, string) (domain.Tokens, error)
	Refresh(context.Context, string) (domain.Tokens, error)
	Logout(context.Context, string) error
	Authenticate(context.Context, string) (domain.User, error)
	UpdateNickname(context.Context, string, string) (domain.User, error)
	ForgotPassword(context.Context, string, string) error
	ResetPassword(context.Context, string, string, string) error
	FindAccount(context.Context, string) (service.AccountLookupResult, error)
}

type AuthHandler struct {
	service      AuthService
	cookieSecure bool
	webOrigin    string
}

func NewAuthHandler(authService AuthService, cfg config.Config) *AuthHandler {
	return &AuthHandler{service: authService, cookieSecure: cfg.CookieSecure, webOrigin: cfg.WebOrigin}
}

func (h *AuthHandler) Authenticator() AuthService {
	return h.service
}

func (h *AuthHandler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// CORS is deliberately restricted to the configured web origin because refresh tokens use cookies.
func (h *AuthHandler) CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && origin != h.webOrigin {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "origin is not allowed"})
			return
		}
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
		}
		if c.Request.Method == http.MethodOptions {
			c.Status(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func (h *AuthHandler) setRefreshCookie(c *gin.Context, raw string, expires time.Time) {
	maxAge := int(time.Until(expires).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     refreshCookie,
		Value:    raw,
		Path:     "/api/v1/auth",
		MaxAge:   maxAge,
		Expires:  expires,
		Secure:   h.cookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *AuthHandler) clearRefreshCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     refreshCookie,
		Value:    "",
		Path:     "/api/v1/auth",
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		Secure:   h.cookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func requestIP(c *gin.Context) string {
	return c.Request.RemoteAddr
}

func bindJSON(c *gin.Context, destination any) bool {
	if err := c.ShouldBindJSON(destination); err != nil {
		respondError(c, http.StatusBadRequest, domain.ErrInvalid)
		return false
	}
	return true
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, domain.ErrInvalid), errors.Is(err, domain.ErrCode):
		return http.StatusBadRequest
	case errors.Is(err, domain.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, domain.ErrTerms):
		return http.StatusUnprocessableEntity
	case errors.Is(err, domain.ErrState):
		return http.StatusGone
	case errors.Is(err, domain.ErrRateLimit):
		return http.StatusTooManyRequests
	case errors.Is(err, domain.ErrUnauthorized):
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

func respondError(c *gin.Context, status int, err error) {
	message := err.Error()
	if status >= http.StatusInternalServerError {
		message = "서버 오류가 발생했습니다"
	}
	c.JSON(status, gin.H{"error": message})
}
