package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/middleware"
)

type loginRequest struct {
	Login    string `json:"login" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var request loginRequest
	if !bindJSON(c, &request) {
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

func (h *AuthHandler) Refresh(c *gin.Context) {
	raw, err := c.Cookie(refreshCookie)
	if err != nil || raw == "" || len(raw) > 256 {
		h.clearRefreshCookie(c)
		respondError(c, http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}
	tokens, err := h.service.Refresh(c.Request.Context(), raw)
	if err != nil {
		h.clearRefreshCookie(c)
		respondError(c, http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}
	h.setRefreshCookie(c, tokens.RefreshToken, tokens.RefreshExpiresAt)
	c.JSON(http.StatusOK, gin.H{"accessToken": tokens.AccessToken, "tokenType": tokens.TokenType, "expiresIn": tokens.ExpiresIn})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	if raw, err := c.Cookie(refreshCookie); err == nil && raw != "" {
		_ = h.service.Logout(c.Request.Context(), raw)
	}
	h.clearRefreshCookie(c)
	c.Status(http.StatusNoContent)
}

func (h *AuthHandler) Me(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": user})
}

type nicknameRequest struct {
	Nickname string `json:"nickname" binding:"required"`
}

func (h *AuthHandler) UpdateNickname(c *gin.Context) {
	request := nicknameRequest{}
	if !bindJSON(c, &request) {
		return
	}
	user, ok := middleware.CurrentUser(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}
	updated, err := h.service.UpdateNickname(c.Request.Context(), user.ID, request.Nickname)
	if err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": updated})
}
