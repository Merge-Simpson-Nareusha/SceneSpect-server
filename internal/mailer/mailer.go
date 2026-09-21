// Package mailer abstracts verification and password-reset delivery.
package mailer

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/smtp"
)

type Sender interface {
	Verification(to, code string) error
	PasswordReset(to, token string) error
}

type SMTP struct {
	Host, Port, User, Password, From string
	AllowInsecure                    bool
}

func (s SMTP) Verification(to, code string) error {
	return s.send(to, "SceneSpect 이메일 인증번호", fmt.Sprintf("인증번호는 %s입니다. 5분 안에 입력해 주세요.\n", code))
}

func (s SMTP) PasswordReset(to, token string) error {
	return s.send(to, "SceneSpect 비밀번호 재설정", fmt.Sprintf("비밀번호 재설정 토큰: %s\n15분 안에 사용해 주세요.\n", token))
}

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

// 개발 환경에서는 외부 메일 서버 없이도 가입 플로우를 확인할 수 있도록 콘솔 출력 어댑터를 제공합니다.
type Console struct{ Logger *log.Logger }

func (c Console) Verification(to, code string) error {
	c.Logger.Printf("verification email to=%s code=%s", to, code)
	return nil
}
func (c Console) PasswordReset(to, token string) error {
	c.Logger.Printf("password reset email to=%s token=%s", to, token)
	return nil
}
