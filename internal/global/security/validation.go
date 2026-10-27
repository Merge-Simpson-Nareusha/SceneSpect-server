package security

import (
	"fmt"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

// # 이메일 정규화 기능
func NormalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 254 || len(strings.SplitN(email, "@", 2)[0]) > 64 {
		return "", response.ErrInvalid
	}
	// 아이디와 기본 닉네임이 모호해지지 않도록 quoted local-part와 제어문자는 받지 않습니다.
	local := strings.SplitN(email, "@", 2)[0]
	for _, r := range local {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '"' || r == '\\' {
			return "", response.ErrInvalid
		}
	}
	return email, nil
}

// # 기본 닉네임 생성 기능
func NicknameBase(email string) string {
	return truncate(strings.SplitN(email, "@", 2)[0], 50)
}

// # 중복 닉네임 후보 생성 기능
func NicknameCandidate(base string, number int) string {
	if number == 1 {
		return base
	}
	suffix := fmt.Sprintf("-%d", number)
	return truncate(base, 50-len(suffix)) + suffix
}

// # 문자열 길이 제한 기능
func truncate(value string, limit int) string {
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit])
	}
	return value
}

// # 닉네임 유효성 확인 기능
func ValidNickname(nickname string) bool {
	if !utf8.ValidString(nickname) || nickname != strings.TrimSpace(nickname) || utf8.RuneCountInString(nickname) < 1 || utf8.RuneCountInString(nickname) > 50 {
		return false
	}
	for _, r := range nickname {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '@' {
			return false
		}
	}
	return true
}
