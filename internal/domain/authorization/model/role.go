// Package model은 애플리케이션 전역 역할과 정확한 역할 비교 규칙을 정의합니다.
//
// Authentication은 자격 증명을 검증해 "누구인가?"에 답하고, Authorization은
// 인증된 주체의 역할로 "무엇을 할 수 있는가?"를 판단합니다. 두 책임을 분리하면
// 접근 정책 변경이 토큰 발급·검증 흐름에 섞이지 않습니다.
package model

// Role is the coarse-grained application role stored in the users table.
type Role string

const (
	UserRole  Role = "USER"
	AdminRole Role = "ADMIN"
)

// HasRole deliberately performs an exact comparison. Role names come from the
// database, so silently accepting a prefix or case-insensitive match could grant
// a privilege that was never assigned.
func HasRole(current string, required Role) bool {
	return current == string(required)
}
