// Package auth translates HTTP authentication requests into domain use cases.
package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/user"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/config"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

const refreshCookie = "scenespect_refresh"

// UseCase is the transport-facing authentication boundary.
type UseCase interface {
	Terms(context.Context) ([]Term, error)
	StartSignup(context.Context, string, string) (SignupStartResult, error)
	SetSignupPassword(context.Context, string, string, string) error
	SendSignupCode(context.Context, string, string) (VerificationResult, error)
	VerifySignupCode(context.Context, string, string) error
	CompleteSignup(context.Context, string, []Consent) (Tokens, error)
	Login(context.Context, string, string, string) (Tokens, error)
	Refresh(context.Context, string) (Tokens, error)
	Logout(context.Context, string) error
	Authenticate(context.Context, string) (user.User, error)
	ForgotPassword(context.Context, string, string) error
	ResetPassword(context.Context, string, string, string) error
	FindAccount(context.Context, string) (AccountLookupResult, error)
	UpdateNickname(context.Context, string, string) (user.User, error)
}

type AuthHandler struct {
	service      UseCase
	cookieSecure bool
	webOrigin    string
}

func NewHandler(authService UseCase, cfg config.Config) *AuthHandler {
	return &AuthHandler{service: authService, cookieSecure: cfg.CookieSecure, webOrigin: cfg.WebOrigin}
}

func (h *AuthHandler) Authenticator() UseCase {
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

func statusFor(err error) int {
	switch {
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrCode):
		return http.StatusBadRequest
	case errors.Is(err, ErrConflict):
		return http.StatusConflict
	case errors.Is(err, ErrTerms):
		return http.StatusUnprocessableEntity
	case errors.Is(err, ErrState):
		return http.StatusGone
	case errors.Is(err, ErrRateLimit):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrUnauthorized):
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

func respondError(c *gin.Context, status int, err error) {
	response.RespondError(c, status, err)
}
