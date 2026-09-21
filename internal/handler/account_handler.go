package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
)

type emailRequest struct {
	Email string `json:"email" binding:"required"`
}

func (h *AuthHandler) PasswordForgot(c *gin.Context) {
	var request emailRequest
	if !bindJSON(c, &request) {
		return
	}
	if err := h.service.ForgotPassword(c.Request.Context(), request.Email, requestIP(c)); err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	// 계정 존재 여부와 관계없이 같은 응답을 반환해 이메일 열거를 방지합니다.
	c.JSON(http.StatusAccepted, gin.H{"message": "계정이 존재하면 재설정 안내를 발송합니다"})
}

type resetRequest struct {
	Token                string `json:"token" binding:"required"`
	Password             string `json:"password" binding:"required"`
	PasswordConfirmation string `json:"passwordConfirmation" binding:"required"`
}

func (h *AuthHandler) PasswordReset(c *gin.Context) {
	var request resetRequest
	if !bindJSON(c, &request) {
		return
	}
	if err := h.service.ResetPassword(c.Request.Context(), request.Token, request.Password, request.PasswordConfirmation); err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"reset": true})
}

type findRequest struct {
	Login string `json:"login" binding:"required"`
}

func (h *AuthHandler) AccountFind(c *gin.Context) {
	var request findRequest
	if !bindJSON(c, &request) {
		return
	}
	result, err := h.service.FindAccount(c.Request.Context(), request.Login)
	if err != nil {
		respondError(c, http.StatusNotFound, domain.ErrUnauthorized)
		return
	}
	c.JSON(http.StatusOK, gin.H{"email": result.Email, "username": result.Username})
}
