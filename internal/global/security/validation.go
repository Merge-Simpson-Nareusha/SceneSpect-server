package security

import (
	"fmt"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

// NormalizeEmail은 이메일을 소문자·공백 제거 형식으로 정규화하고 허용 규칙을 검사합니다.
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

// NicknameBase는 이메일의 @ 앞부분을 기본 닉네임 길이에 맞춰 반환합니다.
func NicknameBase(email string) string {
	return truncate(strings.SplitN(email, "@", 2)[0], 50)
}

// NicknameCandidate는 기본 닉네임에 충돌 순번 suffix를 붙인 후보를 만듭니다.
func NicknameCandidate(base string, number int) string {
	if number == 1 {
		return base
	}
	suffix := fmt.Sprintf("-%d", number)
	return truncate(base, 50-len(suffix)) + suffix
}

// truncate는 UTF-8 문자를 자르지 않도록 rune 단위로 문자열 길이를 제한합니다.
func truncate(value string, limit int) string {
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit])
	}
	return value
}

// ValidNickname은 공백·제어/비표시 문자·@ 포함 여부와 길이 기준으로 닉네임을 검사합니다.
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
