// Package model은 인증 계층 사이에서 공유하는 데이터와 오류를 정의합니다.
// handler, service, repository를 import하지 않아 패키지 간 순환 참조를 방지합니다.
package model

import (
	"strings"
	"time"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// Error values are aliases to the transport-neutral errors owned by the global
// response package. Keeping one error identity lets every adapter use errors.Is.
// 예를 들어 Redis가 ErrState를 반환하면 서비스와 HTTP 핸들러가 같은 값을
// 인식해 각각 "가입 순서 오류"와 적절한 HTTP 상태 코드로 변환할 수 있습니다.
var (
	ErrInvalid      = response.ErrInvalid
	ErrUnauthorized = response.ErrUnauthorized
	ErrConflict     = response.ErrConflict
	ErrTerms        = response.ErrTerms
	ErrState        = response.ErrState
	ErrCode         = response.ErrCode
	ErrRateLimit    = response.ErrRateLimit
)

// User는 인증 서비스가 조회·생성하는 계정 정보를 나타냅니다.
// security.Principal을 공유해 인증 middleware와 데이터 형태를 일치시키되,
// 사용자 프로필 전용 도메인 패키지는 만들지 않습니다.
type User = security.Principal

// MaskEmail은 계정 찾기 응답에서 이메일 아이디 부분을 가려 전체 주소 노출을 줄입니다.
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

type Consent struct {
	// TermID는 사용자가 동의한 약관의 영속 ID입니다. 클라이언트가 보낸
	// 임의의 ID를 그대로 저장하지 않고 repository가 현재 약관과 대조합니다.
	TermID   string `json:"termId"`
	Accepted bool   `json:"accepted"`
}

// Signup은 아직 users 테이블에 저장되지 않은 임시 가입 정보입니다.
// Redis TTL이 만료되면 이 값도 함께 사라지므로 미완료 개인정보를 별도 배치로
// 정리할 필요가 없습니다.
type Signup struct {
	Email, Nickname, PasswordHash string
}

// Term은 버전이 있는 약관 한 건입니다. Required가 true인 항목은 가입 완료
// 트랜잭션에서 반드시 Accepted=true인지 검증해야 합니다.
type Term struct {
	ID       string `json:"id"`
	Code     string `json:"code"`
	Version  string `json:"version"`
	Title    string `json:"title"`
	Content  string `json:"content"`
	Required bool   `json:"required"`
}

type Tokens struct {
	// AccessToken은 응답 본문으로 전달되지만 RefreshToken 원문은 쿠키에만
	// 넣습니다. RefreshToken 필드를 json:"-"로 숨기는 것은 실수로 JSON에
	// 노출하는 것을 막는 마지막 안전장치입니다.
	AccessToken      string    `json:"accessToken"`
	TokenType        string    `json:"tokenType"`
	ExpiresIn        int64     `json:"expiresIn"`
	User             User      `json:"user"`
	RefreshToken     string    `json:"-"`
	RefreshExpiresAt time.Time `json:"-"`
}
