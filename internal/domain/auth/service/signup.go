package service

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	redisdb "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/database/redis"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

var sixDigitCode = regexp.MustCompile(`^[0-9]{6}$`)

// StartSignup은 users를 바로 만들지 않고 Redis에 짧은 가입 세션을 만듭니다.
// 사용자가 중간에 이탈해도 미완료 계정이 남지 않고, 마지막 단계에서만
// 약관과 함께 PostgreSQL 회원을 생성할 수 있습니다. 처리 순서는 요청 IP 제한,
// 이메일 정규화, 기존 계정 확인, 기본 닉네임 검증, Redis 세션 생성입니다.
func (s *AuthService) StartSignup(ctx context.Context, email, requestIP string) (model.SignupStartResult, error) {
	if err := s.cache.Limit(ctx, "signup-start", requestIP, 10, time.Hour); err != nil {
		return model.SignupStartResult{}, err
	}
	normalized, err := security.NormalizeEmail(email)
	if err != nil {
		return model.SignupStartResult{}, err
	}
	exists, err := s.repository.EmailExists(ctx, normalized)
	if err != nil {
		return model.SignupStartResult{}, err
	}
	if exists {
		return model.SignupStartResult{}, model.ErrConflict
	}

	nickname := security.NicknameBase(normalized)
	if !security.ValidNickname(nickname) {
		return model.SignupStartResult{}, model.ErrInvalid
	}
	sessionID := uuid.NewString()
	if err := s.cache.CreateSignup(ctx, sessionID, normalized, nickname); err != nil {
		return model.SignupStartResult{}, err
	}
	return model.SignupStartResult{SignupSessionID: sessionID, Email: normalized, Nickname: nickname, ExpiresIn: int64(redisdb.SignupTTL.Seconds())}, nil
}

// SetSignupPassword는 아직 email 단계인 세션에만 비밀번호를 설정합니다.
// Redis에는 원문 대신 bcrypt 해시를 넣으며 SetPassword가 stage 변경을 원자적으로
// 처리하므로 뒤 단계 요청이 비밀번호 설정을 건너뛸 수 없습니다.
func (s *AuthService) SetSignupPassword(ctx context.Context, sessionID, password, confirmation string) error {
	// 비밀번호 원문은 Redis에도 저장하지 않습니다. 비교가 끝난 즉시 bcrypt 해시만
	// 저장해 Redis가 노출되어도 원문을 복구할 수 없게 합니다.
	if password != confirmation {
		return model.ErrInvalid
	}
	if _, err := uuid.Parse(sessionID); err != nil {
		return model.ErrInvalid
	}
	hash, err := security.HashPassword(password, s.bcryptCost)
	if err != nil {
		return err
	}
	return s.cache.SetPassword(ctx, sessionID, hash)
}

// SendSignupCode는 password 단계의 가입 세션에만 인증번호를 보냅니다.
// 요청 IP와 이메일 단위 횟수 제한에 더해 Redis가 이메일 재전송 대기 시간과
// 가입 세션별 실패 횟수를 검사합니다. 메일에는 원문 코드를 보내고 저장소에는
// 가입 세션에 묶은 HMAC 값만 저장합니다. 코드를 저장한 뒤 메일을 보내므로 발송이
// 실패해도 60초 재전송 대기는 적용됩니다. 발송 서비스 장애 때는 대기가 끝난 뒤
// 다시 보내야 하며 코드는 정상 발송되지 않았다면 사용자가 인증에 쓸 수 없습니다.
func (s *AuthService) SendSignupCode(ctx context.Context, sessionID, requestIP string) (model.VerificationResult, error) {
	// 세션 단계가 password인지 먼저 확인한 뒤에만 코드를 보냅니다. 이 순서 검증이
	// 없으면 인증코드 발송 API를 가입 세션 없이 악용할 수 있습니다.
	signup, err := s.cache.Signup(ctx, sessionID, "password")
	if err != nil {
		return model.VerificationResult{}, err
	}
	if err = s.cache.Limit(ctx, "email-send", signup.Email, 5, time.Hour); err != nil {
		return model.VerificationResult{}, err
	}
	if err = s.cache.Limit(ctx, "email-send-ip", requestIP, 20, time.Hour); err != nil {
		return model.VerificationResult{}, err
	}
	code, err := security.NewCode()
	if err != nil {
		return model.VerificationResult{}, err
	}
	if err = s.cache.SaveCode(ctx, sessionID, signup.Email, security.CodeHash(s.codeKey, sessionID, code)); err != nil {
		return model.VerificationResult{}, err
	}
	if err = s.mailer.Verification(signup.Email, code); err != nil {
		return model.VerificationResult{}, errors.New("메일을 발송하지 못했습니다")
	}
	return model.VerificationResult{ExpiresIn: int64(redisdb.CodeTTL.Seconds()), ResendAfter: 60}, nil
}

// VerifySignupCode는 입력 형식부터 확인하고 일치 여부는 Redis에서 검사합니다.
// 맞는 코드는 한 번만 소비되고 세션은 verified 단계로 이동합니다. 틀린 코드는
// 재전송으로 초기화되지 않는 누적 실패 횟수를 올립니다.
func (s *AuthService) VerifySignupCode(ctx context.Context, sessionID, code string) error {
	// 정규식으로 6자리 숫자를 먼저 제한하고, 실제 비교는 Redis Lua 스크립트가
	// 실패 횟수 증가와 코드 삭제를 한 번에 처리합니다.
	if !sixDigitCode.MatchString(code) {
		return model.ErrCode
	}
	return s.cache.VerifyCode(ctx, sessionID, security.CodeHash(s.codeKey, sessionID, code))
}

// CompleteSignup은 인증이 끝난 임시 세션만 영구 계정으로 승격합니다. repository가
// 현재 필수 약관 동의와 users/user_terms 삽입을 한 DB 트랜잭션에서 처리한 뒤에
// 가입 상태를 지우고 로그인 토큰을 발급합니다. PostgreSQL 커밋 뒤 토큰 발급이
// 실패하면 회원은 이미 만들어진 상태이므로 새 가입 대신 일반 로그인으로 이어가야 합니다.
func (s *AuthService) CompleteSignup(ctx context.Context, sessionID string, consents []model.Consent) (model.Tokens, error) {
	// verified 단계의 Redis 데이터만 영속 회원으로 승격합니다. 이후 약관 검증과
	// users/user_terms 삽입이 성공하면 자동 로그인 토큰을 발급합니다.
	signupData, err := s.cache.Signup(ctx, sessionID, "verified")
	if err != nil {
		return model.Tokens{}, err
	}
	signup := model.Signup{Email: signupData.Email, Nickname: signupData.Nickname, PasswordHash: signupData.PasswordHash}
	user, err := s.repository.CreateUserWithTerms(ctx, signup, consents)
	if err != nil {
		return model.Tokens{}, err
	}
	// 영속 회원 생성 후 임시 상태는 제거합니다. 삭제 실패가 이미 완료된 가입을 되돌리지는 않습니다.
	_ = s.cache.DeleteSignup(ctx, sessionID)
	return s.issueTokens(ctx, user)
}
