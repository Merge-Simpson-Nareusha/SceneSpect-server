package auth

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/database"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

var sixDigitCode = regexp.MustCompile(`^[0-9]{6}$`)

func (s *AuthService) StartSignup(ctx context.Context, email, requestIP string) (SignupStartResult, error) {
	if err := s.cache.Limit(ctx, "signup-start", requestIP, 10, time.Hour); err != nil {
		return SignupStartResult{}, err
	}
	normalized, err := security.NormalizeEmail(email)
	if err != nil {
		return SignupStartResult{}, err
	}
	exists, err := s.repository.EmailExists(ctx, normalized)
	if err != nil {
		return SignupStartResult{}, err
	}
	if exists {
		return SignupStartResult{}, ErrConflict
	}

	nickname := security.NicknameBase(normalized)
	if !security.ValidNickname(nickname) {
		return SignupStartResult{}, ErrInvalid
	}
	sessionID := uuid.NewString()
	if err := s.cache.CreateSignup(ctx, sessionID, normalized, nickname); err != nil {
		return SignupStartResult{}, err
	}
	return SignupStartResult{SignupSessionID: sessionID, Email: normalized, Nickname: nickname, ExpiresIn: int64(database.SignupTTL.Seconds())}, nil
}

func (s *AuthService) SetSignupPassword(ctx context.Context, sessionID, password, confirmation string) error {
	if password != confirmation {
		return ErrInvalid
	}
	if _, err := uuid.Parse(sessionID); err != nil {
		return ErrInvalid
	}
	hash, err := security.HashPassword(password, s.bcryptCost)
	if err != nil {
		return err
	}
	return s.cache.SetPassword(ctx, sessionID, hash)
}

func (s *AuthService) SendSignupCode(ctx context.Context, sessionID, requestIP string) (VerificationResult, error) {
	signup, err := s.cache.Signup(ctx, sessionID, "password")
	if err != nil {
		return VerificationResult{}, err
	}
	if err = s.cache.Limit(ctx, "email-send", signup.Email, 5, time.Hour); err != nil {
		return VerificationResult{}, err
	}
	if err = s.cache.Limit(ctx, "email-send-ip", requestIP, 20, time.Hour); err != nil {
		return VerificationResult{}, err
	}
	code, err := security.NewCode()
	if err != nil {
		return VerificationResult{}, err
	}
	if err = s.cache.SaveCode(ctx, sessionID, signup.Email, security.CodeHash(s.codeKey, sessionID, code)); err != nil {
		return VerificationResult{}, err
	}
	if err = s.mailer.Verification(signup.Email, code); err != nil {
		return VerificationResult{}, errors.New("메일을 발송하지 못했습니다")
	}
	return VerificationResult{ExpiresIn: int64(database.CodeTTL.Seconds()), ResendAfter: 60}, nil
}

func (s *AuthService) VerifySignupCode(ctx context.Context, sessionID, code string) error {
	if !sixDigitCode.MatchString(code) {
		return ErrCode
	}
	return s.cache.VerifyCode(ctx, sessionID, security.CodeHash(s.codeKey, sessionID, code))
}

func (s *AuthService) CompleteSignup(ctx context.Context, sessionID string, consents []Consent) (Tokens, error) {
	signupData, err := s.cache.Signup(ctx, sessionID, "verified")
	if err != nil {
		return Tokens{}, err
	}
	signup := Signup{Email: signupData.Email, Nickname: signupData.Nickname, PasswordHash: signupData.PasswordHash}
	user, err := s.repository.CreateUserWithTerms(ctx, signup, consents)
	if err != nil {
		return Tokens{}, err
	}
	// 영속 회원 생성 후 임시 상태는 제거합니다. 삭제 실패가 이미 완료된 가입을 되돌리지는 않습니다.
	_ = s.cache.DeleteSignup(ctx, sessionID)
	return s.issueTokens(ctx, user)
}
