package security

import (
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

// HashPassword는 길이 정책을 확인한 뒤 bcrypt 해시를 생성합니다.
func HashPassword(raw string, cost int) (string, error) {
	// bcrypt의 72-byte 상한을 명시적으로 검사해 긴 비밀번호의 잘림을 방지합니다.
	if !utf8.ValidString(raw) || utf8.RuneCountInString(raw) < 12 || len(raw) > 72 {
		return "", response.ErrInvalid
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), cost)
	return string(hash), err
}

// IsPasswordValid는 입력한 비밀번호가 저장된 bcrypt 해시와 일치하는지 확인합니다.
func IsPasswordValid(raw, encoded string) bool {
	return bcrypt.CompareHashAndPassword([]byte(encoded), []byte(raw)) == nil
}
