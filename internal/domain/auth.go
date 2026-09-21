// Package domain은 인증 유스케이스가 공유하는 데이터와 오류를 정의합니다.
// Gin, PostgreSQL, Redis 같은 외부 기술은 이 패키지에 들어오지 않습니다.
package domain

import (
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalid      = errors.New("입력값을 확인해 주세요")
	ErrUnauthorized = errors.New("인증 정보가 올바르지 않거나 만료되었습니다")
	ErrConflict     = errors.New("이미 사용 중인 이메일 또는 닉네임입니다")
	ErrTerms        = errors.New("현재 필수 약관에 모두 동의해야 합니다")
	ErrState        = errors.New("가입 세션이 만료되었거나 진행 순서가 올바르지 않습니다")
	ErrCode         = errors.New("인증코드가 올바르지 않거나 만료되었습니다")
	ErrRateLimit    = errors.New("요청 횟수를 초과했습니다. 잠시 후 다시 시도해 주세요")
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

type Term struct {
	ID       string `json:"id"`
	Code     string `json:"code"`
	Version  string `json:"version"`
	Title    string `json:"title"`
	Content  string `json:"content"`
	Required bool   `json:"required"`
}

type Consent struct {
	TermID   string `json:"termId"`
	Accepted bool   `json:"accepted"`
}

type Signup struct {
	Email, Nickname, PasswordHash string
}

type Tokens struct {
	AccessToken      string    `json:"accessToken"`
	TokenType        string    `json:"tokenType"`
	ExpiresIn        int64     `json:"expiresIn"`
	User             User      `json:"user"`
	RefreshToken     string    `json:"-"`
	RefreshExpiresAt time.Time `json:"-"`
}

type OAuthIdentity struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
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
