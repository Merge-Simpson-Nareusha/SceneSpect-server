// Package handler는 인증 API의 HTTP 요청·응답과 쿠키를 담당합니다.
// 업무 규칙은 service에 위임하고, JSON 필드와 상태 코드는 이 패키지에서 관리합니다.
package handler

import (
	"context"
	"net/http"
	"strings"
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
	UpdateNickname(context.Context, string, string) (model.User, error)
	UpdateProfile(context.Context, string, string, string) (model.User, error)
	UpdateDisplayTheme(context.Context, string, string) (model.User, error)
	ChangePassword(context.Context, string, string, string, string) error
}

type OAuthUseCase interface {
	Begin(context.Context, string, string) (string, error)
	Callback(context.Context, string, string, string) (model.OAuthCallbackResult, error)
	StartEmailVerification(context.Context, string, string, string) (model.VerificationResult, error)
	VerifyEmail(context.Context, string, string) error
	CompleteSignup(context.Context, string, string, []model.Consent) (model.Tokens, error)
}

// AuthHandler는 인증 요청을 service에 전달하고 JSON 응답과 쿠키를 구성합니다.
type AuthHandler struct {
	service      UseCase
	oauth        OAuthUseCase
	cookieSecure bool
	webOrigin    string
	apiBaseURL   string
}

// # 인증 핸들러 생성 기능
func NewHandler(authService UseCase, cfg config.Config) *AuthHandler {
	return NewHandlerWithOAuth(authService, nil, cfg)
}

func NewHandlerWithOAuth(authService UseCase, oauthService OAuthUseCase, cfg config.Config) *AuthHandler {
	return &AuthHandler{
		service:      authService,
		oauth:        oauthService,
		cookieSecure: cfg.CookieSecure,
		webOrigin:    cfg.WebOrigin,
		apiBaseURL:   cfg.APIBaseURL,
	}
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
		oauthCallback := strings.HasPrefix(c.Request.URL.Path, "/api/v1/auth/oauth/") && strings.HasSuffix(c.Request.URL.Path, "/callback")
		apiOrigin := origin != "" && origin == h.apiBaseURL
		webOrigin := origin != "" && origin == h.webOrigin
		if origin != "" && !webOrigin && !apiOrigin && !oauthCallback {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "origin is not allowed"})
			return
		}
		if webOrigin || apiOrigin {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
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
	return response.StatusFor(err)
}

// # API 오류 응답 작성 기능
func respondError(c *gin.Context, status int, err error) {
	response.RespondError(c, status, err)
}
