// Package middleware contains request authentication and role authorization middleware.
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
)

const UserKey = "user"

type Authenticator interface {
	Authenticate(context.Context, string) (domain.User, error)
}

func Authenticate(authenticator Authenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		parts := strings.Fields(c.GetHeader("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			abortUnauthorized(c)
			return
		}
		user, err := authenticator.Authenticate(c.Request.Context(), parts[1])
		if err != nil {
			abortUnauthorized(c)
			return
		}
		c.Set(UserKey, user)
		c.Next()
	}
}

func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, ok := CurrentUser(c)
		if !ok || user.Role != role {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "접근 권한이 없습니다"})
			return
		}
		c.Next()
	}
}

func CurrentUser(c *gin.Context) (domain.User, bool) {
	value, ok := c.Get(UserKey)
	if !ok {
		return domain.User{}, false
	}
	user, ok := value.(domain.User)
	return user, ok
}

func abortUnauthorized(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": domain.ErrUnauthorized.Error()})
}
