// Package model은 USER·ADMIN 역할 이름과 역할 비교 규칙을 정의합니다.
package model

// Role은 계정에 저장되는 기본 인가 역할입니다.
type Role string

const (
	UserRole  Role = "USER"
	AdminRole Role = "ADMIN"
)

// # 역할 권한 비교 기능
func HasRole(current string, required Role) bool {
	return current == string(required)
}
