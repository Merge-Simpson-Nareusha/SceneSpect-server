package middleware

import (
	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/authorization/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/authorization/service"
	authmiddleware "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/middleware"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

// RequireRole is the HTTP adapter for the authorization policy.
//
// 인증 미들웨어가 먼저 실행되어야 CurrentUser가 값을 반환합니다. 따라서
// 라우터에서는 Authenticate → RequireRole 순서로 등록해야 합니다.
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
