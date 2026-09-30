package response

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// StatusFor는 도메인 오류 종류를 대응하는 HTTP 상태 코드로 변환합니다.
func StatusFor(err error) int {
	switch {
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrCode):
		return http.StatusBadRequest
	case errors.Is(err, ErrConflict):
		return http.StatusConflict
	case errors.Is(err, ErrTerms):
		return http.StatusUnprocessableEntity
	case errors.Is(err, ErrState):
		return http.StatusGone
	case errors.Is(err, ErrRateLimit):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrUnauthorized):
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

// BindJSON은 요청 JSON을 구조체로 읽고 형식이 잘못되면 공통 400 응답을 보냅니다.
func BindJSON(c *gin.Context, destination any) bool {
	if err := c.ShouldBindJSON(destination); err != nil {
		RespondError(c, http.StatusBadRequest, ErrInvalid)
		return false
	}
	return true
}

// RespondError는 JSON 형식으로 오류를 반환하고 내부 서버 오류 메시지는 감춥니다.
func RespondError(c *gin.Context, status int, err error) {
	message := err.Error()
	if status >= http.StatusInternalServerError {
		message = "서버 오류가 발생했습니다"
	}
	c.JSON(status, gin.H{"error": message})
}

// Unauthorized는 인증 실패 응답을 보내고 현재 Gin 요청 체인을 중단합니다.
func Unauthorized(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrUnauthorized.Error()})
}

// Forbidden은 인가 실패 응답을 보내고 현재 Gin 요청 체인을 중단합니다.
func Forbidden(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "접근 권한이 없습니다"})
}
