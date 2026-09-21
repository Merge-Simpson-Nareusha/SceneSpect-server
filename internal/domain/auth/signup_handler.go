package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

func (h *AuthHandler) SignupTerms(c *gin.Context) {
	terms, err := h.service.Terms(c.Request.Context())
	if err != nil {
		respondError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"terms": terms})
}

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
