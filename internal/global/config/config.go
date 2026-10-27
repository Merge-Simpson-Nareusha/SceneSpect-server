package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Environment, Address, DatabaseURL, RedisURL          string
	JWTKey, CodeKey                                      []byte
	Issuer, Audience, WebOrigin                          string
	AccessTTL, RefreshTTL                                time.Duration
	CookieSecure                                         bool
	BcryptCost                                           int
	SMTPHost, SMTPPort, SMTPUser, SMTPPassword, MailFrom string
	SMTPInsecure                                         bool
}

// # 환경 설정 로드 기능
func Load() (Config, error) {
	c := Config{
		Environment: env("APP_ENV", "development"), Address: env("HTTP_ADDR", ":8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"), RedisURL: os.Getenv("REDIS_URL"),
		Issuer: "scenespect-api", Audience: "scenespect-web", WebOrigin: env("WEB_ORIGIN", "http://localhost:3000"),
		SMTPHost: os.Getenv("SMTP_HOST"), SMTPPort: env("SMTP_PORT", "587"),
		SMTPUser: os.Getenv("SMTP_USER"), SMTPPassword: os.Getenv("SMTP_PASSWORD"), MailFrom: os.Getenv("MAIL_FROM"),
	}
	var err error
	if c.JWTKey, err = secret("JWT_SECRET"); err != nil {
		return c, err
	}
	if c.CodeKey, err = secret("CODE_SECRET"); err != nil {
		return c, err
	}
	if string(c.JWTKey) == string(c.CodeKey) {
		return c, errors.New("JWT_SECRET and CODE_SECRET must differ")
	}
	if c.CookieSecure, err = strconv.ParseBool(env("COOKIE_SECURE", "true")); err != nil {
		return c, fmt.Errorf("COOKIE_SECURE: %w", err)
	}
	if c.SMTPInsecure, err = strconv.ParseBool(env("SMTP_ALLOW_INSECURE", "false")); err != nil {
		return c, fmt.Errorf("SMTP_ALLOW_INSECURE: %w", err)
	}
	if c.BcryptCost, err = strconv.Atoi(env("BCRYPT_COST", "12")); err != nil || c.BcryptCost < 10 || c.BcryptCost > 14 {
		return c, errors.New("BCRYPT_COST must be between 10 and 14")
	}
	if c.AccessTTL, err = time.ParseDuration(env("ACCESS_TOKEN_TTL", "15m")); err != nil || c.AccessTTL < time.Minute || c.AccessTTL > 30*time.Minute {
		return c, errors.New("ACCESS_TOKEN_TTL must be between 1m and 30m")
	}
	if c.RefreshTTL, err = time.ParseDuration(env("REFRESH_TOKEN_TTL", "336h")); err != nil || c.RefreshTTL < time.Hour || c.RefreshTTL > 30*24*time.Hour {
		return c, errors.New("REFRESH_TOKEN_TTL must be between 1h and 720h")
	}
	if c.DatabaseURL == "" || c.RedisURL == "" || c.SMTPHost == "" || c.MailFrom == "" {
		return c, errors.New("DATABASE_URL, REDIS_URL, SMTP_HOST and MAIL_FROM are required")
	}
	u, err := url.Parse(c.WebOrigin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return c, errors.New("WEB_ORIGIN must be an exact http(s) origin without a trailing slash")
	}
	if c.Environment != "development" && c.Environment != "test" && c.Environment != "production" {
		return c, errors.New("APP_ENV must be development, test or production")
	}
	if c.Environment == "production" && (!c.CookieSecure || c.SMTPInsecure || u.Scheme != "https") {
		return c, errors.New("production requires secure cookies, HTTPS WEB_ORIGIN and SMTP STARTTLS")
	}
	return c, nil
}

// # 필수 비밀 설정 조회 기능
func secret(name string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(os.Getenv(name))
	if err != nil || len(b) < 32 {
		return nil, fmt.Errorf("%s must be base64 containing at least 32 random bytes", name)
	}
	return b, nil
}

// # 환경 변수 조회 기능
func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
