// Package security는 인증 서비스가 공유하는 토큰·비밀번호·난수·입력 검증 기능을 제공합니다.
package security

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

// Claims는 Access Token에서 사용자, 세션, 역할과 토큰 만료 정보를 읽습니다.
type Claims struct {
	SessionID string `json:"sid"`
	TokenUse  string `json:"token_use"`
	Role      string `json:"role"`
	jwt.RegisteredClaims
}

// TokenManager는 서명된 Access Token을 발급하고 검증하는 설정을 보관합니다.
type TokenManager struct {
	Key              []byte
	Issuer, Audience string
	TTL              time.Duration
}

// # JWT 발급 기능
func (m TokenManager) Issue(userID, familyID, role string) (string, error) {
	now := time.Now()
	claims := Claims{
		SessionID: familyID,
		TokenUse:  "access",
		Role:      role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    m.Issuer,
			Audience:  jwt.ClaimStrings{m.Audience},
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.TTL)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.Key)
}

// # JWT 검증 및 파싱 기능
func (m TokenManager) Parse(raw string) (*Claims, error) {
	if len(raw) > 4096 {
		return nil, response.ErrUnauthorized
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(_ *jwt.Token) (any, error) {
		return m.Key, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(m.Issuer), jwt.WithAudience(m.Audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !token.Valid || claims.TokenUse != "access" || claims.IssuedAt == nil || claims.NotBefore == nil {
		return nil, response.ErrUnauthorized
	}
	if _, err = uuid.Parse(claims.Subject); err != nil {
		return nil, response.ErrUnauthorized
	}
	if _, err = uuid.Parse(claims.SessionID); err != nil {
		return nil, response.ErrUnauthorized
	}
	return claims, nil
}
