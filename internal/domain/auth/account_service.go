package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/user"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

func (s *AuthService) UpdateNickname(ctx context.Context, userID, nickname string) (user.User, error) {
	if !security.ValidNickname(nickname) {
		return user.User{}, ErrInvalid
	}
	if err := s.repository.UpdateNickname(ctx, userID, nickname); err != nil {
		return user.User{}, err
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
	current, err := s.repository.UserByEmail(ctx, normalized)
	if errors.Is(err, ErrUnauthorized) {
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

func (s *AuthService) ResetPassword(ctx context.Context, rawToken, password, confirmation string) error {
	if password != confirmation || len(rawToken) > 256 {
		return ErrInvalid
	}
	hash, err := security.HashPassword(password, s.bcryptCost)
	if err != nil {
		return err
	}
	reset, err := s.cache.ConsumeReset(ctx, rawToken)
	if err != nil {
		return ErrUnauthorized
	}
	current, err := s.repository.UserByID(ctx, reset.UserID)
	if err != nil || current.PasswordVersion != reset.PasswordVersion {
		return ErrUnauthorized
	}
	return s.repository.ResetPassword(ctx, current.ID, hash)
}

func (s *AuthService) FindAccount(ctx context.Context, login string) (AccountLookupResult, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	var current user.User
	var err error
	if strings.Contains(login, "@") {
		login, err = security.NormalizeEmail(login)
		if err != nil {
			return AccountLookupResult{}, ErrUnauthorized
		}
		current, err = s.repository.UserByEmail(ctx, login)
	} else {
		current, err = s.repository.UserByLogin(ctx, login)
	}
	if err != nil {
		return AccountLookupResult{}, err
	}
	return AccountLookupResult{Email: user.MaskEmail(current.Email), Username: current.Username}, nil
}

func isBlocked(current user.User) bool {
	return strings.EqualFold(current.Status, "BLOCKED")
}
