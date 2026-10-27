package mailer

import "log"

// Console은 개발 중 SMTP 설정 없이 가입·재설정 흐름을 확인하기 위한 Sender 구현입니다.
// 인증 코드와 재설정 토큰을 로그에 그대로 출력하므로 main에서 development 환경에만 연결합니다.
type Console struct{ Logger *log.Logger }

// # 이메일 인증 코드 출력 기능
func (c Console) Verification(to, code string) error {
	c.Logger.Printf("verification email to=%s code=%s", to, code)
	return nil
}

// # 비밀번호 재설정 링크 출력 기능
func (c Console) PasswordReset(to, token string) error {
	c.Logger.Printf("password reset email to=%s token=%s", to, token)
	return nil
}
