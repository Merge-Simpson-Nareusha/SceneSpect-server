package handler

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	authmiddleware "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/middleware"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

type oauthEmailRequest struct {
	OAuthSessionID string `json:"oauthSessionId" binding:"required"`
	Email          string `json:"email" binding:"required"`
}

type oauthEmailVerifyRequest struct {
	OAuthSessionID string `json:"oauthSessionId" binding:"required"`
	Code           string `json:"code" binding:"required"`
}

type oauthCompleteRequest struct {
	OAuthSessionID string          `json:"oauthSessionId" binding:"required"`
	Nickname       string          `json:"nickname"`
	Consents       []model.Consent `json:"consents" binding:"required"`
}

func (h *AuthHandler) OAuthStart(c *gin.Context) {
	authorizationURL, err := h.oauth.Begin(c.Request.Context(), c.Param("provider"), "")
	if err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.Redirect(http.StatusFound, authorizationURL)
}

func (h *AuthHandler) OAuthLinkStart(c *gin.Context) {
	user, ok := authmiddleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	authorizationURL, err := h.oauth.Begin(c.Request.Context(), c.Param("provider"), user.ID)
	if err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"authorizationUrl": authorizationURL})
}

func (h *AuthHandler) OAuthCallback(c *gin.Context) {
	provider := strings.ToLower(c.Param("provider"))
	if c.Request.Method == http.MethodPost {
		if err := c.Request.ParseForm(); err != nil {
			response.RespondError(c, http.StatusBadRequest, model.ErrInvalid)
			return
		}
	}
	if c.Request.FormValue("error") != "" {
		c.Redirect(http.StatusSeeOther, h.webOrigin+"/oauth/error?provider="+url.QueryEscape(provider)+"&reason=denied")
		return
	}
	result, err := h.oauth.Callback(c.Request.Context(), provider, c.Request.FormValue("code"), c.Request.FormValue("state"))
	if err != nil {
		if statusFor(err) >= http.StatusInternalServerError {
			respondError(c, statusFor(err), err)
			return
		}
		c.Redirect(http.StatusSeeOther, h.webOrigin+"/oauth/error?provider="+url.QueryEscape(provider)+"&reason=invalid_response")
		return
	}
	if result.Tokens != nil {
		h.setRefreshCookie(c, result.Tokens.RefreshToken, result.Tokens.RefreshExpiresAt)
		c.Redirect(http.StatusSeeOther, h.webOrigin+"/oauth/callback?provider="+url.QueryEscape(provider))
		return
	}
	query := url.Values{}
	query.Set("oauthSessionId", result.SignupSessionID)
	query.Set("emailRequired", map[bool]string{true: "true", false: "false"}[result.EmailRequired])
	c.Redirect(http.StatusSeeOther, h.webOrigin+"/oauth/complete?"+query.Encode())
}

func (h *AuthHandler) OAuthEmailSend(c *gin.Context) {
	var request oauthEmailRequest
	if !response.BindJSON(c, &request) {
		return
	}
	result, err := h.oauth.StartEmailVerification(c.Request.Context(), request.OAuthSessionID, request.Email, requestIP(c))
	if err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"expiresIn": result.ExpiresIn, "resendAfter": result.ResendAfter})
}

func (h *AuthHandler) OAuthEmailVerify(c *gin.Context) {
	var request oauthEmailVerifyRequest
	if !response.BindJSON(c, &request) {
		return
	}
	if err := h.oauth.VerifyEmail(c.Request.Context(), request.OAuthSessionID, request.Code); err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"verified": true})
}

func (h *AuthHandler) OAuthComplete(c *gin.Context) {
	var request oauthCompleteRequest
	if !response.BindJSON(c, &request) {
		return
	}
	tokens, err := h.oauth.CompleteSignup(c.Request.Context(), request.OAuthSessionID, request.Nickname, request.Consents)
	if err != nil {
		respondError(c, statusFor(err), err)
		return
	}
	h.setRefreshCookie(c, tokens.RefreshToken, tokens.RefreshExpiresAt)
	c.JSON(http.StatusCreated, gin.H{"accessToken": tokens.AccessToken, "tokenType": tokens.TokenType, "expiresIn": tokens.ExpiresIn, "user": tokens.User})
}
