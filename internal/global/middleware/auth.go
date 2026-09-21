// Package middleware contains request authentication and role authorization middleware.
package middleware

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

const UserKey = "user"

type Authenticator interface {
	Authenticate(context.Context, string) (security.Principal, error)
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
			response.Forbidden(c)
			return
		}
		c.Next()
	}
}

func CurrentUser(c *gin.Context) (security.Principal, bool) {
	value, ok := c.Get(UserKey)
	if !ok {
		return security.Principal{}, false
	}
	current, ok := value.(security.Principal)
	return current, ok
}

func abortUnauthorized(c *gin.Context) {
	response.Unauthorized(c)
}
