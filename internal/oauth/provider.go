// Package oauth defines extension points for future social login providers.
package oauth

import (
	"context"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
)

// OAuthProvider는 Google·Apple·Kakao·X 연동을 같은 계정 연결 흐름에 끼울 확장 지점입니다.
// 실제 공급자 검증은 각 공급자의 JWKS·state·PKCE 정책을 확정한 뒤 별도 구현합니다.
type OAuthProvider interface {
	Name() string
	Exchange(ctx context.Context, code, redirectURI string) (domain.OAuthIdentity, error)
}

type OAuthRegistry struct{ providers map[string]OAuthProvider }

func NewOAuthRegistry(providers ...OAuthProvider) OAuthRegistry {
	r := OAuthRegistry{providers: map[string]OAuthProvider{}}
	for _, p := range providers {
		r.providers[p.Name()] = p
	}
	return r
}
func (r OAuthRegistry) Provider(name string) (OAuthProvider, bool) {
	p, ok := r.providers[name]
	return p, ok
}
