package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	authmiddleware "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/middleware"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

// # 내 정보 조회 기능
func (h *AuthHandler) Me(c *gin.Context) {
	current, ok := authmiddleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": current})
}

// # 닉네임 수정 요청 처리 기능
func (h *AuthHandler) NicknameUpdate(c *gin.Context) {
	var request nicknameRequest
	if !response.BindJSON(c, &request) {
		return
	}
	current, ok := authmiddleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	updated, err := h.service.UpdateNickname(c.Request.Context(), current.ID, request.Nickname)
	if err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": updated})
}

// # 프로필과 화면 설정 수정 요청 처리 기능
func (h *AuthHandler) ProfileUpdate(c *gin.Context) {
	var request profileRequest
	if !response.BindJSON(c, &request) {
		return
	}
	current, ok := authmiddleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	updated, err := h.service.UpdateProfile(c.Request.Context(), current.ID, request.Nickname, request.AvatarURL)
	if err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": updated})
}

// # 화면 테마 수정 요청 처리 기능
func (h *AuthHandler) DisplayThemeUpdate(c *gin.Context) {
	var request displayThemeRequest
	if !response.BindJSON(c, &request) {
		return
	}
	current, ok := authmiddleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	updated, err := h.service.UpdateDisplayTheme(c.Request.Context(), current.ID, request.DisplayTheme)
	if err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": updated})
}

// # 로그인된 사용자의 비밀번호 변경 요청 처리 기능
func (h *AuthHandler) PasswordChange(c *gin.Context) {
	var request changePasswordRequest
	if !response.BindJSON(c, &request) {
		return
	}
	current, ok := authmiddleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	if err := h.service.ChangePassword(c.Request.Context(), current.ID, request.CurrentPassword, request.Password, request.PasswordConfirmation); err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.Status(http.StatusNoContent)
}

// # 비밀번호 찾기 요청 처리 기능
func (h *AuthHandler) PasswordForgot(c *gin.Context) {
	var request emailRequest
	if !response.BindJSON(c, &request) {
		return
	}
	if err := h.service.ForgotPassword(c.Request.Context(), request.Email, requestIP(c)); err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "계정이 존재하면 재설정 안내를 발송합니다"})
}

// # 비밀번호 재설정 요청 처리 기능
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

// # 계정 찾기 요청 처리 기능
func (h *AuthHandler) AccountFind(c *gin.Context) {
	var request findRequest
	if !response.BindJSON(c, &request) {
		return
	}
	result, err := h.service.FindAccount(c.Request.Context(), request.Login)
	if err != nil {
		respondError(c, http.StatusNotFound, model.ErrUnauthorized)
		return
	}
	c.JSON(http.StatusOK, gin.H{"email": result.Email, "username": result.Username})
}
