// Package mailer는 인증번호·비밀번호 재설정 안내를 발송합니다.
package mailer

type Sender interface {
	// Verification은 가입 과정의 이메일 소유 확인 코드를 전달합니다.
	Verification(to, code string) error
	// PasswordReset은 비밀번호 재설정용 단기 토큰을 전달합니다.
	PasswordReset(to, token string) error
}
