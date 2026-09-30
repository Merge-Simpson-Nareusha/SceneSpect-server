// Package handler는 인증 API의 HTTP 요청·응답과 쿠키를 담당합니다.
// 업무 규칙은 service에 위임하고, JSON 필드와 상태 코드는 이 패키지에서 관리합니다.
package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/config"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

const refreshCookie = "scenespect_refresh"

// UseCase는 HTTP handler가 인증 서비스에 요청을 전달할 때 사용하는 계약입니다.
type UseCase interface {
	Terms(context.Context) ([]model.Term, error)
	StartSignup(context.Context, string, string) (model.SignupStartResult, error)
	SetSignupPassword(context.Context, string, string, string) error
	SendSignupCode(context.Context, string, string) (model.VerificationResult, error)
	VerifySignupCode(context.Context, string, string) error
	CompleteSignup(context.Context, string, []model.Consent) (model.Tokens, error)
	Login(context.Context, string, string, string) (model.Tokens, error)
	Refresh(context.Context, string) (model.Tokens, error)
	Logout(context.Context, string) error
	Authenticate(context.Context, string) (model.User, error)
	ForgotPassword(context.Context, string, string) error
	ResetPassword(context.Context, string, string, string) error
	FindAccount(context.Context, string) (model.AccountLookupResult, error)
}

// AuthHandler는 인증 요청을 service에 전달하고 JSON 응답과 쿠키를 구성합니다.
type AuthHandler struct {
	service      UseCase
	cookieSecure bool
	webOrigin    string
}

// # 인증 핸들러 생성 기능
func NewHandler(authService UseCase, cfg config.Config) *AuthHandler {
	return &AuthHandler{service: authService, cookieSecure: cfg.CookieSecure, webOrigin: cfg.WebOrigin}
}

// # 인증 서비스 조회 기능
func (h *AuthHandler) Authenticator() UseCase {
	return h.service
}

// # 헬스 상태 응답 기능
func (h *AuthHandler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// # CORS 미들웨어 구성 기능
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
			c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}
		if c.Request.Method == http.MethodOptions {
			c.Status(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// # Refresh Token 쿠키 설정 기능
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

// # Refresh Token 쿠키 삭제 기능
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

// # 요청 IP 조회 기능
func requestIP(c *gin.Context) string {
	return c.Request.RemoteAddr
}

// # API 오류 상태 코드 결정 기능
func statusFor(err error) int {
	switch {
	case errors.Is(err, model.ErrInvalid), errors.Is(err, model.ErrCode):
		return http.StatusBadRequest
	case errors.Is(err, model.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, model.ErrTerms):
		return http.StatusUnprocessableEntity
	case errors.Is(err, model.ErrState):
		return http.StatusGone
	case errors.Is(err, model.ErrRateLimit):
		return http.StatusTooManyRequests
	case errors.Is(err, model.ErrUnauthorized):
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

// # API 오류 응답 작성 기능
func respondError(c *gin.Context, status int, err error) {
	response.RespondError(c, status, err)
}
