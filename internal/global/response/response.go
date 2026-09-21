package response

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

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

func BindJSON(c *gin.Context, destination any) bool {
	if err := c.ShouldBindJSON(destination); err != nil {
		RespondError(c, http.StatusBadRequest, ErrInvalid)
		return false
	}
	return true
}

func RespondError(c *gin.Context, status int, err error) {
	message := err.Error()
	if status >= http.StatusInternalServerError {
		message = "서버 오류가 발생했습니다"
	}
	c.JSON(status, gin.H{"error": message})
}

func Unauthorized(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrUnauthorized.Error()})
}

func Forbidden(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "접근 권한이 없습니다"})
}
