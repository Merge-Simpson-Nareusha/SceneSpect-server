// Package middleware contains request authentication middleware shared by domains.
// 역할(인가) 정책은 domain/authorization 패키지가 담당합니다. 이렇게 나누면
// 토큰을 확인하는 인증(Authentication)과 권한을 확인하는 인가(Authorization)를
// 서로 다른 팀이 독립적으로 수정할 수 있습니다.
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

func CurrentUser(c *gin.Context) (security.Principal, bool) {
	value, ok := c.Get(UserKey)
	if !ok {
		return security.Principal{}, false
	}
	current, ok := value.(security.Principal)
	return current, ok
}

func abortUnauthorized(c *gin.Context) {
	// 인증 실패 사유를 세분화하지 않고 같은 응답을 반환해 토큰 존재 여부가 노출되지 않게 합니다.
	response.Unauthorized(c)
}
