package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

// SignupTerms는 화면이 가입을 시작하거나 인증을 마친 뒤 현재 적용 중인 약관을
// 읽을 때 사용합니다. 화면이 보낸 약관을 그대로 저장하는 API는 따로 없습니다.
func (h *AuthHandler) SignupTerms(c *gin.Context) {
	terms, err := h.service.Terms(c.Request.Context())
	if err != nil {
		respondError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"terms": terms})
}

// SignupStart는 이메일 하나를 서비스에 전달합니다. 임시 가입 세션과 기본 닉네임은
// 서버가 만들며 응답의 세션 ID를 다음 단계 요청들이 이어서 사용합니다.
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

// SignupPassword는 확인용 비밀번호까지 받은 뒤 서비스에 넘깁니다.
// 이 요청이 성공한 뒤에만 가입 세션이 다음 email verification 단계에 도달합니다.
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

// SignupEmailSend는 세션 ID와 요청 IP를 전달합니다. 실제 재전송 횟수와 대기 시간은
// 서버가 계산하므로 클라이언트 화면의 카운트다운을 보안 제한으로 취급하지 않습니다.
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

// SignupEmailVerify는 사용자 입력을 서비스에 전달하고 성공한 경우에만 인증 완료를
// 응답합니다. 코드 비교와 Redis의 단계 변경은 service/cache 경계 안에서 처리됩니다.
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

// SignupComplete는 현재 약관 동의 여부를 서버에서 검증한 뒤 회원과 Refresh Token을
// 만듭니다. Access Token은 JSON 응답에, Refresh Token 원문은 HttpOnly 쿠키에만 담습니다.
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
