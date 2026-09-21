package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
)

type signupStartRequest struct {
	Email string `json:"email" binding:"required"`
}

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
	if !bindJSON(c, &request) {
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

type passwordRequest struct {
	SignupSessionID      string `json:"signupSessionId" binding:"required"`
	Password             string `json:"password" binding:"required"`
	PasswordConfirmation string `json:"passwordConfirmation" binding:"required"`
}

func (h *AuthHandler) SignupPassword(c *gin.Context) {
	var request passwordRequest
	if !bindJSON(c, &request) {
		return
	}
	if err := h.service.SetSignupPassword(c.Request.Context(), request.SignupSessionID, request.Password, request.PasswordConfirmation); err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"next": "email_verification"})
}

type sessionRequest struct {
	SignupSessionID string `json:"signupSessionId" binding:"required"`
}

func (h *AuthHandler) SignupEmailSend(c *gin.Context) {
	var request sessionRequest
	if !bindJSON(c, &request) {
		return
	}
	result, err := h.service.SendSignupCode(c.Request.Context(), request.SignupSessionID, requestIP(c))
	if err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"expiresIn": result.ExpiresIn, "resendAfter": result.ResendAfter})
}

type verifyRequest struct {
	SignupSessionID string `json:"signupSessionId" binding:"required"`
	Code            string `json:"code" binding:"required"`
}

func (h *AuthHandler) SignupEmailVerify(c *gin.Context) {
	var request verifyRequest
	if !bindJSON(c, &request) {
		return
	}
	if err := h.service.VerifySignupCode(c.Request.Context(), request.SignupSessionID, request.Code); err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"verified": true, "next": "terms"})
}

type consentRequest struct {
	SignupSessionID string           `json:"signupSessionId" binding:"required"`
	Consents        []domain.Consent `json:"consents" binding:"required"`
}

func (h *AuthHandler) SignupComplete(c *gin.Context) {
	var request consentRequest
	if !bindJSON(c, &request) {
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
