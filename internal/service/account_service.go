package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/security"
)

func (s *AuthService) UpdateNickname(ctx context.Context, userID, nickname string) (domain.User, error) {
	if !security.ValidNickname(nickname) {
		return domain.User{}, domain.ErrInvalid
	}
	if err := s.repository.UpdateNickname(ctx, userID, nickname); err != nil {
		return domain.User{}, err
	}
	return s.repository.UserByID(ctx, userID)
}

func (s *AuthService) ForgotPassword(ctx context.Context, email, requestIP string) error {
	normalized, err := security.NormalizeEmail(email)
	if err != nil {
		return nil
	}
	if err = s.cache.Limit(ctx, "password-forgot", requestIP, 5, time.Hour); err != nil {
		return err
	}
	user, err := s.repository.UserByEmail(ctx, normalized)
	if errors.Is(err, domain.ErrUnauthorized) {
		return nil
	}
	if err != nil {
		return err
	}
	raw, err := security.RandomToken()
	if err != nil {
		return err
	}
	if err = s.cache.SaveReset(ctx, raw, user); err != nil {
		return err
	}
	if err = s.mailer.PasswordReset(user.Email, raw); err != nil {
		return errors.New("메일을 발송하지 못했습니다")
	}
	return nil
}

func (s *AuthService) ResetPassword(ctx context.Context, rawToken, password, confirmation string) error {
	if password != confirmation || len(rawToken) > 256 {
		return domain.ErrInvalid
	}
	hash, err := security.HashPassword(password, s.bcryptCost)
	if err != nil {
		return err
	}
	reset, err := s.cache.ConsumeReset(ctx, rawToken)
	if err != nil {
		return domain.ErrUnauthorized
	}
	user, err := s.repository.UserByID(ctx, reset.UserID)
	if err != nil || user.PasswordVersion != reset.PasswordVersion {
		return domain.ErrUnauthorized
	}
	return s.repository.ResetPassword(ctx, user.ID, hash)
}

func (s *AuthService) FindAccount(ctx context.Context, login string) (AccountLookupResult, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	var user domain.User
	var err error
	if strings.Contains(login, "@") {
		login, err = security.NormalizeEmail(login)
		if err != nil {
			return AccountLookupResult{}, domain.ErrUnauthorized
		}
		user, err = s.repository.UserByEmail(ctx, login)
	} else {
		user, err = s.repository.UserByLogin(ctx, login)
	}
	if err != nil {
		return AccountLookupResult{}, err
	}
	return AccountLookupResult{Email: domain.MaskEmail(user.Email), Username: user.Username}, nil
}

func isBlocked(user domain.User) bool {
	return strings.EqualFold(user.Status, "BLOCKED")
}
