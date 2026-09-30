package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

// Login은 JSON 입력을 검증하고 service 결과를 브라우저에서 사용할 두 채널로 나눕니다.
// Access Token은 짧은 API 인증용 응답이고 Refresh Token은 재발급에만 쓰는 쿠키입니다.
func (h *AuthHandler) Login(c *gin.Context) {
	// 로그인 응답에는 짧은 수명의 Access Token만 JSON으로 넣고,
	// 장기 Refresh Token은 HttpOnly 쿠키로 설정합니다.
	var request loginRequest
	if !response.BindJSON(c, &request) {
		return
	}
	tokens, err := h.service.Login(c.Request.Context(), request.Login, request.Password, requestIP(c))
	if err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	h.setRefreshCookie(c, tokens.RefreshToken, tokens.RefreshExpiresAt)
	c.JSON(http.StatusOK, gin.H{
		"accessToken": tokens.AccessToken,
		"tokenType":   tokens.TokenType,
		"expiresIn":   tokens.ExpiresIn,
		"user":        tokens.User,
	})
}

// Refresh는 브라우저가 자동으로 보낸 HttpOnly 쿠키를 읽습니다. 성공 응답에서
// 새 쿠키로 교체하므로 클라이언트는 Refresh Token 원문을 직접 다루지 않습니다.
func (h *AuthHandler) Refresh(c *gin.Context) {
	// 쿠키가 없거나 회전 검증에 실패하면 쿠키를 먼저 지워 재사용을 막습니다.
	raw, err := c.Cookie(refreshCookie)
	if err != nil || raw == "" || len(raw) > 256 {
		h.clearRefreshCookie(c)
		respondError(c, http.StatusUnauthorized, model.ErrUnauthorized)
		return
	}
	tokens, err := h.service.Refresh(c.Request.Context(), raw)
	if err != nil {
		h.clearRefreshCookie(c)
		respondError(c, http.StatusUnauthorized, model.ErrUnauthorized)
		return
	}
	h.setRefreshCookie(c, tokens.RefreshToken, tokens.RefreshExpiresAt)
	c.JSON(http.StatusOK, gin.H{"accessToken": tokens.AccessToken, "tokenType": tokens.TokenType, "expiresIn": tokens.ExpiresIn})
}

// Logout은 토큰이 있으면 저장소에서도 폐기하고 항상 브라우저 쿠키를 지웁니다.
// 저장소 폐기에 성공한 이전 토큰은 다시 제출해도 회전되지 않습니다.
func (h *AuthHandler) Logout(c *gin.Context) {
	// 토큰 폐기가 실패해도 브라우저 쿠키는 삭제합니다. 클라이언트에 남은 토큰을
	// 계속 보내지 않게 하는 것이 로그아웃 요청의 최소 보장입니다.
	if raw, err := c.Cookie(refreshCookie); err == nil && raw != "" {
		_ = h.service.Logout(c.Request.Context(), raw)
	}
	h.clearRefreshCookie(c)
	c.Status(http.StatusNoContent)
}
