package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

// PasswordForgot은 계정이 실제로 있는지와 무관하게 같은 성공 메시지를 반환합니다.
// 서비스도 미등록 이메일에는 메일을 보내지 않지만 이 응답은 달라지지 않습니다.
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

// PasswordReset은 HTTP 요청을 service에 전달하고 성공 여부만 JSON 본문으로 돌려줍니다.
// 비밀번호 저장과 세션 폐기는 service/repository가 담당하며 실패는 HTTP 오류 상태로 표현합니다.
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

// AccountFind는 찾은 아이디와 마스킹 이메일을 반환합니다. 존재하지 않는 계정은
// 404이므로 계정 존재 여부를 알 수 있는 경로이며 비밀번호 인증을 대신하지 않습니다.
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
