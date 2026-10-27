package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

// # 가입 약관 조회 요청 처리 기능
func (h *AuthHandler) SignupTerms(c *gin.Context) {
	terms, err := h.service.Terms(c.Request.Context())
	if err != nil {
		respondError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"terms": terms})
}

// # 가입 시작 요청 처리 기능
func (h *AuthHandler) SignupStart(c *gin.Context) {
	var request signupStartRequest
	if !response.BindJSON(c, &request) {
		return
	}
	result, err := h.service.StartSignup(c.Request.Context(), request.Email, requestIP(c))
	if err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"signupSessionId": result.SignupSessionID,
		"email":           result.Email,
		"nickname":        result.Nickname,
		"expiresIn":       result.ExpiresIn,
	})
}

// # 가입 비밀번호 설정 요청 처리 기능
func (h *AuthHandler) SignupPassword(c *gin.Context) {
	var request passwordRequest
	if !response.BindJSON(c, &request) {
		return
	}
	if err := h.service.SetSignupPassword(c.Request.Context(), request.SignupSessionID, request.Password, request.PasswordConfirmation); err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"next": "email_verification"})
}

// # 이메일 인증 코드 발송 요청 처리 기능
func (h *AuthHandler) SignupEmailSend(c *gin.Context) {
	var request sessionRequest
	if !response.BindJSON(c, &request) {
		return
	}
	result, err := h.service.SendSignupCode(c.Request.Context(), request.SignupSessionID, requestIP(c))
	if err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"expiresIn": result.ExpiresIn, "resendAfter": result.ResendAfter})
}

// # 이메일 인증 코드 확인 요청 처리 기능
func (h *AuthHandler) SignupEmailVerify(c *gin.Context) {
	var request verifyRequest
	if !response.BindJSON(c, &request) {
		return
	}
	if err := h.service.VerifySignupCode(c.Request.Context(), request.SignupSessionID, request.Code); err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"verified": true, "next": "terms"})
}

// # 회원가입 완료 요청 처리 기능
func (h *AuthHandler) SignupComplete(c *gin.Context) {
	var request consentRequest
	if !response.BindJSON(c, &request) {
		return
	}
	tokens, err := h.service.CompleteSignup(c.Request.Context(), request.SignupSessionID, request.Consents)
	if err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	h.setRefreshCookie(c, tokens.RefreshToken, tokens.RefreshExpiresAt)
	c.JSON(http.StatusCreated, gin.H{
		"accessToken": tokens.AccessToken,
		"tokenType":   tokens.TokenType,
		"expiresIn":   tokens.ExpiresIn,
		"user":        tokens.User,
	})
}
