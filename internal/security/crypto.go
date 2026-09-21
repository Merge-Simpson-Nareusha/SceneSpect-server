// Package security contains authentication primitives shared by the service layer.
package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
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
	c := Claims{SessionID: familyID, TokenUse: "access", Role: role, RegisteredClaims: jwt.RegisteredClaims{
		Subject: userID, Issuer: m.Issuer, Audience: jwt.ClaimStrings{m.Audience},
		ID: uuid.NewString(), IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(m.TTL)),
	}}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(m.Key)
}

// Parse는 서명뿐 아니라 알고리즘·발급자·대상·만료·토큰 용도까지 검증합니다.
func (m TokenManager) Parse(raw string) (*Claims, error) {
	if len(raw) > 4096 {
		return nil, domain.ErrUnauthorized
	}
	c := &Claims{}
	t, err := jwt.ParseWithClaims(raw, c, func(_ *jwt.Token) (any, error) { return m.Key, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(m.Issuer), jwt.WithAudience(m.Audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !t.Valid || c.TokenUse != "access" || c.IssuedAt == nil || c.NotBefore == nil {
		return nil, domain.ErrUnauthorized
	}
	if _, err = uuid.Parse(c.Subject); err != nil {
		return nil, domain.ErrUnauthorized
	}
	if _, err = uuid.Parse(c.SessionID); err != nil {
		return nil, domain.ErrUnauthorized
	}
	return c, nil
}

func RandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func TokenHash(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// 6자리 코드는 엔트로피가 낮아 단순 SHA-256 대신 서버 비밀키가 필요한 HMAC으로 저장합니다.
func CodeHash(key []byte, session, code string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(session + ":" + code))
	return hex.EncodeToString(h.Sum(nil))
}

func NewCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func NormalizeEmail(raw string) (string, error) {
	e := strings.ToLower(strings.TrimSpace(raw))
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || len(e) > 254 || len(strings.SplitN(e, "@", 2)[0]) > 64 {
		return "", domain.ErrInvalid
	}
	// 아이디와 기본 닉네임이 모호해지지 않도록 quoted local-part와 제어문자는 받지 않습니다.
	local := strings.SplitN(e, "@", 2)[0]
	for _, r := range local {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '"' || r == '\\' {
			return "", domain.ErrInvalid
		}
	}
	return e, nil
}

func NicknameBase(email string) string {
	return truncate(strings.SplitN(email, "@", 2)[0], 50)
}

func NicknameCandidate(base string, n int) string {
	if n == 1 {
		return base
	}
	suffix := fmt.Sprintf("-%d", n)
	return truncate(base, 50-len(suffix)) + suffix
}

func truncate(s string, limit int) string {
	r := []rune(s)
	if len(r) > limit {
		return string(r[:limit])
	}
	return s
}

func ValidNickname(n string) bool {
	if !utf8.ValidString(n) || n != strings.TrimSpace(n) || utf8.RuneCountInString(n) < 1 || utf8.RuneCountInString(n) > 50 {
		return false
	}
	for _, r := range n {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '@' {
			return false
		}
	}
	return true
}

func HashPassword(raw string, cost int) (string, error) {
	// bcrypt의 72-byte 상한을 명시적으로 검사해 긴 비밀번호의 잘림을 방지합니다.
	if !utf8.ValidString(raw) || utf8.RuneCountInString(raw) < 12 || len(raw) > 72 {
		return "", domain.ErrInvalid
	}
	h, err := bcrypt.GenerateFromPassword([]byte(raw), cost)
	return string(h), err
}

// IsPasswordValid verifies a bcrypt hash without exposing the stored hash to callers.
func IsPasswordValid(raw, encoded string) bool {
	return bcrypt.CompareHashAndPassword([]byte(encoded), []byte(raw)) == nil
}
