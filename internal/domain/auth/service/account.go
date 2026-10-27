package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
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
	return s.repository.ResetPassword(ctx, current.ID, hash)
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

// # 계정 잠금 상태 확인 기능
func isBlocked(current model.User) bool {
	return strings.EqualFold(current.Status, "BLOCKED")
}
