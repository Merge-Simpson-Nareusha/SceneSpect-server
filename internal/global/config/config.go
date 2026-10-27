package config

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
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
	Issuer, Audience, WebOrigin, APIBaseURL              string
	AccessTTL, RefreshTTL                                time.Duration
	CookieSecure                                         bool
	BcryptCost                                           int
	SMTPHost, SMTPPort, SMTPUser, SMTPPassword, MailFrom string
	SMTPInsecure                                         bool
	MediaStorageDir                                      string
	MediaMaxImageBytes                                   int64
	OAuth                                                OAuthConfig
}

type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
}

type OAuthAppleConfig struct {
	ClientID      string
	TeamID        string
	KeyID         string
	PrivateKeyPEM []byte
}

type OAuthConfig struct {
	Google OAuthProviderConfig
	Kakao  OAuthProviderConfig
	X      OAuthProviderConfig
	Apple  OAuthAppleConfig
}

// # 환경 설정 로드 기능
func Load() (Config, error) {
	c := Config{
		Environment: env("APP_ENV", "development"), Address: env("HTTP_ADDR", ":8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"), RedisURL: os.Getenv("REDIS_URL"),
		Issuer: "scenespect-api", Audience: "scenespect-web", WebOrigin: env("WEB_ORIGIN", "https://localhost:5173"),
		APIBaseURL: env("API_BASE_URL", "http://localhost:8080"), MediaStorageDir: env("MEDIA_STORAGE_DIR", "./uploads"),
		SMTPHost: os.Getenv("SMTP_HOST"), SMTPPort: env("SMTP_PORT", "587"),
		SMTPUser: os.Getenv("SMTP_USER"), SMTPPassword: os.Getenv("SMTP_PASSWORD"), MailFrom: os.Getenv("MAIL_FROM"),
		OAuth: OAuthConfig{
			Google: OAuthProviderConfig{ClientID: os.Getenv("OAUTH_GOOGLE_CLIENT_ID"), ClientSecret: os.Getenv("OAUTH_GOOGLE_CLIENT_SECRET")},
			Kakao:  OAuthProviderConfig{ClientID: os.Getenv("OAUTH_KAKAO_CLIENT_ID"), ClientSecret: os.Getenv("OAUTH_KAKAO_CLIENT_SECRET")},
			X:      OAuthProviderConfig{ClientID: os.Getenv("OAUTH_X_CLIENT_ID"), ClientSecret: os.Getenv("OAUTH_X_CLIENT_SECRET")},
			Apple:  OAuthAppleConfig{ClientID: os.Getenv("OAUTH_APPLE_CLIENT_ID"), TeamID: os.Getenv("OAUTH_APPLE_TEAM_ID"), KeyID: os.Getenv("OAUTH_APPLE_KEY_ID")},
		},
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
	if c.MediaMaxImageBytes, err = strconv.ParseInt(env("MEDIA_MAX_IMAGE_BYTES", "5242880"), 10, 64); err != nil || c.MediaMaxImageBytes < 1024 || c.MediaMaxImageBytes > 20*1024*1024 {
		return c, errors.New("MEDIA_MAX_IMAGE_BYTES must be between 1024 and 20971520")
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
	apiURL, err := url.Parse(c.APIBaseURL)
	if err != nil || apiURL.Host == "" || apiURL.User != nil || apiURL.RawQuery != "" || apiURL.Fragment != "" || apiURL.Path != "" || (apiURL.Scheme != "http" && apiURL.Scheme != "https") {
		return c, errors.New("API_BASE_URL must be an exact http(s) origin without a trailing slash")
	}
	if err = validateOAuthConfig(&c.OAuth); err != nil {
		return c, err
	}
	if c.Environment == "production" && (!c.CookieSecure || c.SMTPInsecure || u.Scheme != "https" || apiURL.Scheme != "https") {
		return c, errors.New("production requires secure cookies, HTTPS WEB_ORIGIN and API_BASE_URL, and SMTP STARTTLS")
	}
	return c, nil
}

func validateOAuthConfig(config *OAuthConfig) error {
	if (config.Google.ClientID == "") != (config.Google.ClientSecret == "") {
		return errors.New("OAUTH_GOOGLE_CLIENT_ID and OAUTH_GOOGLE_CLIENT_SECRET must be configured together")
	}
	if (config.Kakao.ClientID == "") != (config.Kakao.ClientSecret == "") {
		return errors.New("OAUTH_KAKAO_CLIENT_ID and OAUTH_KAKAO_CLIENT_SECRET must be configured together")
	}
	if config.X.ClientSecret != "" && config.X.ClientID == "" {
		return errors.New("OAUTH_X_CLIENT_ID is required when OAUTH_X_CLIENT_SECRET is set")
	}
	appleSet := config.Apple.ClientID != "" || config.Apple.TeamID != "" || config.Apple.KeyID != "" || os.Getenv("OAUTH_APPLE_PRIVATE_KEY_B64") != ""
	if appleSet {
		if config.Apple.ClientID == "" || config.Apple.TeamID == "" || config.Apple.KeyID == "" {
			return errors.New("Apple OAuth requires OAUTH_APPLE_CLIENT_ID, OAUTH_APPLE_TEAM_ID and OAUTH_APPLE_KEY_ID")
		}
		key, err := base64.StdEncoding.DecodeString(os.Getenv("OAUTH_APPLE_PRIVATE_KEY_B64"))
		if err != nil || len(key) == 0 {
			return errors.New("OAUTH_APPLE_PRIVATE_KEY_B64 must contain a base64-encoded PEM private key")
		}
		block, _ := pem.Decode(key)
		if block == nil {
			return errors.New("OAUTH_APPLE_PRIVATE_KEY_B64 does not contain a PEM private key")
		}
		var privateKey *ecdsa.PrivateKey
		if parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes); parseErr == nil {
			privateKey, _ = parsed.(*ecdsa.PrivateKey)
		}
		if privateKey == nil {
			privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		}
		if err != nil || privateKey == nil || privateKey.Curve.Params().BitSize != 256 {
			return errors.New("Apple OAuth private key must be a P-256 EC private key")
		}
		config.Apple.PrivateKeyPEM = key
	}
	return nil
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
