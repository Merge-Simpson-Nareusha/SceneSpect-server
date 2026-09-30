package middleware

import (
	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/authorization/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/authorization/service"
	authmiddleware "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/middleware"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

// # 역할 기반 접근 제어 기능
func RequireRole(role model.Role) gin.HandlerFunc {
	checker := service.Checker{}
	return func(c *gin.Context) {
		current, ok := authmiddleware.CurrentUser(c)
		if !ok || !checker.Can(current, role) {
			response.Forbidden(c)
			return
		}
		c.Next()
	}
}
