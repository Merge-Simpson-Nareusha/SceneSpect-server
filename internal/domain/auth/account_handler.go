package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

func (h *AuthHandler) PasswordForgot(c *gin.Context) {
	var request emailRequest
	if !response.BindJSON(c, &request) {
		return
	}
	if err := h.service.ForgotPassword(c.Request.Context(), request.Email, requestIP(c)); err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	// 계정 존재 여부와 관계없이 같은 응답을 반환해 이메일 열거를 방지합니다.
	c.JSON(http.StatusAccepted, gin.H{"message": "계정이 존재하면 재설정 안내를 발송합니다"})
}

func (h *AuthHandler) PasswordReset(c *gin.Context) {
	var request resetRequest
	if !response.BindJSON(c, &request) {
		return
	}
	if err := h.service.ResetPassword(c.Request.Context(), request.Token, request.Password, request.PasswordConfirmation); err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"reset": true})
}

func (h *AuthHandler) AccountFind(c *gin.Context) {
	var request findRequest
	if !response.BindJSON(c, &request) {
		return
	}
	result, err := h.service.FindAccount(c.Request.Context(), request.Login)
	if err != nil {
		respondError(c, http.StatusNotFound, ErrUnauthorized)
		return
	}
	c.JSON(http.StatusOK, gin.H{"email": result.Email, "username": result.Username})
}
