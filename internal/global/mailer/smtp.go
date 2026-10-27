package mailer

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
)

// SMTP는 실제 메일 서버에 연결하는 Sender 구현입니다.
// 인증 정보는 환경 설정에서 주입하며, AllowInsecure는 개발 환경 외에는 켜지 않아야 합니다.
type SMTP struct {
	Host, Port, User, Password, From string
	AllowInsecure                    bool
}

// # 이메일 인증 코드 전송 기능
func (s SMTP) Verification(to, code string) error {
	return s.send(to, "SceneSpect 이메일 인증번호", fmt.Sprintf("인증번호는 %s입니다. 5분 안에 입력해 주세요.\n", code))
}

// # 비밀번호 재설정 메일 전송 기능
func (s SMTP) PasswordReset(to, token string) error {
	return s.send(to, "SceneSpect 비밀번호 재설정", fmt.Sprintf("비밀번호 재설정 토큰: %s\n15분 안에 사용해 주세요.\n", token))
}

// # SMTP 메일 발송 기능
func (s SMTP) send(to, subject, body string) error {
	addr := s.Host + ":" + s.Port
	msg := []byte("From: " + s.From + "\r\n" + "To: " + to + "\r\n" + "Subject: " + subject + "\r\n" + "Content-Type: text/plain; charset=UTF-8\r\n\r\n" + body)
	auth := smtp.PlainAuth("", s.User, s.Password, s.Host)
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err = c.StartTLS(&tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: s.AllowInsecure}); err != nil {
			return err
		}
	} else if !s.AllowInsecure {
		return fmt.Errorf("SMTP server does not support STARTTLS")
	}
	if s.User != "" {
		if err = c.Auth(auth); err != nil {
			return err
		}
	}
	if err = c.Mail(s.From); err != nil {
		return err
	}
	if err = c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err = w.Write(msg); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
