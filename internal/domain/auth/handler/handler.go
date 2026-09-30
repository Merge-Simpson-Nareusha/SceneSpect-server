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

// UseCase is the transport-facing authentication boundary.
// 핸들러는 구체적인 PostgreSQL/Redis 구현을 몰라도 되므로, 이 인터페이스를
// 기준으로 요청을 서비스에 전달하고 응답·쿠키만 조립합니다.
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

type AuthHandler struct {
	service      UseCase
	cookieSecure bool
	webOrigin    string
}

// NewHandler는 쿠키 정책과 허용 Origin을 핸들러에 주입합니다. 환경변수를
// 핸들러가 직접 읽지 않게 해야 테스트에서 개발/운영 정책을 쉽게 바꿀 수 있습니다.
func NewHandler(authService UseCase, cfg config.Config) *AuthHandler {
	return &AuthHandler{service: authService, cookieSecure: cfg.CookieSecure, webOrigin: cfg.WebOrigin}
}

func (h *AuthHandler) Authenticator() UseCase {
	return h.service
}

// Health는 외부 의존성까지 점검하지 않는 프로세스 생존 확인용 엔드포인트입니다.
// PostgreSQL/Redis readiness는 Docker healthcheck와 서버 시작 시 Ping에서 확인합니다.
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
			c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}
		if c.Request.Method == http.MethodOptions {
			c.Status(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func (h *AuthHandler) setRefreshCookie(c *gin.Context, raw string, expires time.Time) {
	// Refresh Token은 JavaScript가 읽을 수 없는 HttpOnly 쿠키로만 보냅니다.
	// Path를 인증 API로 제한하면 다른 경로 요청에 토큰이 자동 전송되지 않습니다.
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
	// 로그아웃이나 재발급 실패 시 브라우저의 오래된 토큰도 즉시 제거합니다.
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
	// 도메인 오류를 HTTP 상태로 바꾸는 책임은 transport 계층에 둡니다.
	// 서비스는 Gin을 몰라야 하므로 상태 코드를 직접 반환하지 않습니다.
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

func respondError(c *gin.Context, status int, err error) {
	response.RespondError(c, status, err)
}
