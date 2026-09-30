// Package middleware는 Access Token을 검증해 인증된 요청을 다음 handler로 전달합니다.
// 역할 기반 접근 정책은 domain/authorization 패키지가 담당합니다.
package middleware

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

const UserKey = "user"

// Authenticator는 Bearer Token을 검증하고 인증된 사용자를 반환하는 서비스 계약입니다.
type Authenticator interface {
	Authenticate(context.Context, string) (security.Principal, error)
}

// Authenticate는 Authorization 헤더를 검증하고 통과한 사용자를 Gin context에 저장합니다.
func Authenticate(authenticator Authenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Authorization 헤더는 "Bearer <access-token>" 두 조각이어야 합니다.
		// 형식이 조금이라도 다르면 토큰 파싱 전에 거부해 모호한 입력을 차단합니다.
		parts := strings.Fields(c.GetHeader("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			abortUnauthorized(c)
			return
		}
		// 토큰의 서명·만료·사용자 상태 검증은 auth 서비스에 위임합니다.
		// 미들웨어는 HTTP 요청을 다음 핸들러로 넘길지 결정하는 역할만 합니다.
		user, err := authenticator.Authenticate(c.Request.Context(), parts[1])
		if err != nil {
			abortUnauthorized(c)
			return
		}
		// 이후 핸들러가 DB를 다시 조회하지 않도록 검증된 주체를 컨텍스트에 보관합니다.
		c.Set(UserKey, user)
		c.Next()
	}
}

// CurrentUser는 Authenticate middleware가 저장한 인증 사용자를 꺼냅니다.
func CurrentUser(c *gin.Context) (security.Principal, bool) {
	value, ok := c.Get(UserKey)
	if !ok {
		return security.Principal{}, false
	}
	current, ok := value.(security.Principal)
	return current, ok
}

// abortUnauthorized는 요청 처리를 중단하고 공통 401 응답을 반환합니다.
func abortUnauthorized(c *gin.Context) {
	// 인증 실패 사유를 세분화하지 않고 같은 응답을 반환해 토큰 존재 여부가 노출되지 않게 합니다.
	response.Unauthorized(c)
}
