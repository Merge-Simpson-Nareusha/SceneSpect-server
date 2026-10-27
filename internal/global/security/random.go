package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

// # 임의 토큰 생성 기능
func RandomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// # 토큰 해시 생성 기능
func TokenHash(raw string) string {
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// # 인증 코드 해시 생성 기능
func CodeHash(key []byte, session, code string) string {
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write([]byte(session + ":" + code))
	return hex.EncodeToString(hash.Sum(nil))
}

// # 인증 코드 생성 기능
func NewCode() (string, error) {
	number, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", number.Int64()), nil
}
