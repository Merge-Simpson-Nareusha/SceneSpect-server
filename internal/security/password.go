package security

import (
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
)

func HashPassword(raw string, cost int) (string, error) {
	// bcrypt의 72-byte 상한을 명시적으로 검사해 긴 비밀번호의 잘림을 방지합니다.
	if !utf8.ValidString(raw) || utf8.RuneCountInString(raw) < 12 || len(raw) > 72 {
		return "", domain.ErrInvalid
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), cost)
	return string(hash), err
}

func IsPasswordValid(raw, encoded string) bool {
	return bcrypt.CompareHashAndPassword([]byte(encoded), []byte(raw)) == nil
}
