// Package security contains authentication primitives shared by the service layer.
package security

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

type Claims struct {
	SessionID string `json:"sid"`
	TokenUse  string `json:"token_use"`
	Role      string `json:"role"`
	jwt.RegisteredClaims
}

type TokenManager struct {
	Key              []byte
	Issuer, Audience string
	TTL              time.Duration
}

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

// Parse는 서명뿐 아니라 알고리즘·발급자·대상·만료·토큰 용도까지 검증합니다.
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
