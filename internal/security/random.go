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

func RandomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func TokenHash(raw string) string {
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// CodeHash는 6자리 코드가 Redis에서 유출되어도 원문을 추측하기 어렵게 HMAC으로 저장합니다.
func CodeHash(key []byte, session, code string) string {
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write([]byte(session + ":" + code))
	return hex.EncodeToString(hash.Sum(nil))
}

func NewCode() (string, error) {
	number, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", number.Int64()), nil
}
