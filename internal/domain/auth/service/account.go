package service

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	redisdb "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/database/redis"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// # 비밀번호 재설정 요청 처리 기능
func (s *AuthService) ForgotPassword(ctx context.Context, email, requestIP string) error {
	normalized, err := security.NormalizeEmail(email)
	if err != nil {
		return nil
	}
	if err = s.cache.Limit(ctx, "password-forgot", requestIP, 5, time.Hour); err != nil {
		return err
	}
	current, err := s.repository.UserByEmail(ctx, normalized)
	if errors.Is(err, model.ErrUnauthorized) {
		return nil
	}
	if err != nil {
		return err
	}
	raw, err := security.RandomToken()
	if err != nil {
		return err
	}
	if err = s.cache.SaveReset(ctx, raw, current.ID, current.PasswordVersion); err != nil {
		return err
	}
	if err = s.mailer.PasswordReset(current.Email, raw); err != nil {
		return errors.New("메일을 발송하지 못했습니다")
	}
	return nil
}

// # 비밀번호 재설정 기능
func (s *AuthService) ResetPassword(ctx context.Context, rawToken, password, confirmation string) error {
	if password != confirmation || len(rawToken) > 256 {
		return model.ErrInvalid
	}
	hash, err := security.HashPassword(password, s.bcryptCost)
	if err != nil {
		return err
	}
	reset, err := s.cache.ConsumeReset(ctx, rawToken)
	if err != nil {
		return model.ErrUnauthorized
	}
	current, err := s.repository.UserByID(ctx, reset.UserID)
	if err != nil || current.PasswordVersion != reset.PasswordVersion {
		return model.ErrUnauthorized
	}
	return s.repository.ResetPassword(ctx, current.ID, hash, reset.PasswordVersion)
}

// # 계정 정보 찾기 기능
func (s *AuthService) FindAccount(ctx context.Context, login string) (model.AccountLookupResult, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	var current model.User
	var err error
	if strings.Contains(login, "@") {
		login, err = security.NormalizeEmail(login)
		if err != nil {
			return model.AccountLookupResult{}, model.ErrUnauthorized
		}
		current, err = s.repository.UserByEmail(ctx, login)
	} else {
		current, err = s.repository.UserByLogin(ctx, login)
	}
	if err != nil {
		return model.AccountLookupResult{}, err
	}
	return model.AccountLookupResult{Email: model.MaskEmail(current.Email), Username: current.Username}, nil
}

// # 사용자 닉네임 수정 기능
func (s *AuthService) UpdateNickname(ctx context.Context, userID, nickname string) (model.User, error) {
	if !security.ValidNickname(nickname) {
		return model.User{}, model.ErrInvalid
	}
	return s.repository.UpdateNickname(ctx, userID, nickname)
}

// # 프로필과 화면 테마 수정 기능
func (s *AuthService) UpdateProfile(ctx context.Context, userID, nickname, avatarURL string) (model.User, error) {
	nickname = strings.TrimSpace(nickname)
	avatarURL = strings.TrimSpace(avatarURL)
	if !security.ValidNickname(nickname) || !validMediaURL(avatarURL) {
		return model.User{}, model.ErrInvalid
	}
	return s.repository.UpdateProfile(ctx, userID, nickname, avatarURL)
}

func (s *AuthService) UpdateDisplayTheme(ctx context.Context, userID, displayTheme string) (model.User, error) {
	displayTheme = strings.ToUpper(strings.TrimSpace(displayTheme))
	if displayTheme != "LIGHT" && displayTheme != "DARK" && displayTheme != "SYSTEM" {
		return model.User{}, model.ErrInvalid
	}
	return s.repository.UpdateDisplayTheme(ctx, userID, displayTheme)
}

// # 로그인된 사용자의 비밀번호 변경 기능
func (s *AuthService) ChangePassword(ctx context.Context, userID, currentPassword, password, confirmation string) error {
	if password != confirmation {
		return model.ErrInvalid
	}
	current, err := s.repository.UserByID(ctx, userID)
	if err != nil {
		return model.ErrUnauthorized
	}
	if !security.IsPasswordValid(currentPassword, current.PasswordHash) {
		return model.ErrUnauthorized
	}
	hash, err := security.HashPassword(password, s.bcryptCost)
	if err != nil {
		return err
	}
	return s.repository.ChangePassword(ctx, userID, current.PasswordHash, current.PasswordVersion, hash)
}

func (s *AuthService) Signup(ctx context.Context, signupSessionID, stage string) (redisdb.SignupData, error) {
	return s.cache.Signup(ctx, signupSessionID, stage)
}

func (s *AuthService) DeleteSignup(ctx context.Context, signupSessionID string) error {
	return s.cache.DeleteSignup(ctx, signupSessionID)
}

func validMediaURL(value string) bool {
	if value == "" {
		return true
	}
	if strings.HasPrefix(value, "/media/") {
		return !strings.Contains(value, "..") && !strings.ContainsAny(value, "?#\\") && len(value) <= 512
	}
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && len(value) <= 512
}

// # 계정 잠금 상태 확인 기능
func isBlocked(current model.User) bool {
	return strings.EqualFold(current.Status, "BLOCKED")
}
