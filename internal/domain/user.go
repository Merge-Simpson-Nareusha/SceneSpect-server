package domain

import (
	"strings"
	"time"
)

type User struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	Username        string    `json:"username"`
	Nickname        string    `json:"nickname"`
	Role            string    `json:"role"`
	Status          string    `json:"status"`
	EmailVerified   bool      `json:"emailVerified"`
	CreatedAt       time.Time `json:"createdAt"`
	PasswordHash    string    `json:"-"`
	PasswordVersion int64     `json:"-"`
}

// MaskEmail은 계정 찾기 응답에서 이메일 전체가 노출되지 않도록 일부만 반환합니다.
func MaskEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	local := []rune(parts[0])
	if len(local) == 0 {
		return "*@" + parts[1]
	}
	keep := 1
	if len(local) >= 4 {
		keep = 2
	}
	stars := len(local) - keep
	if stars < 1 {
		stars = 1
	}
	return string(local[:keep]) + strings.Repeat("*", stars) + "@" + parts[1]
}
