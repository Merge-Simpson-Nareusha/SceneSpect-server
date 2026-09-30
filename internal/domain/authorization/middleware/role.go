package middleware

import (
	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/authorization/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/authorization/service"
	authmiddleware "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/middleware"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

// RequireRole은 인증된 사용자가 지정된 역할을 가졌는지 확인하는 Gin middleware를 반환합니다.
// 라우터에서 Authenticate 다음에 등록해야 인증 사용자 정보를 읽을 수 있습니다.
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
