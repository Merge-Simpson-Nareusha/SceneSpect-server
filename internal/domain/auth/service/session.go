package service

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// Login은 IP별 요청 제한을 적용한 뒤 이메일 또는 고정 아이디로 회원을 조회하고
// bcrypt 해시를 확인합니다. 계정이 차단됐거나 이메일 미인증이거나 비밀번호가
// 틀린 경우에도 동일한 인증 오류를 반환해 로그인 응답에서 실패 사유를 나누지 않습니다.
func (s *AuthService) Login(ctx context.Context, login, password, requestIP string) (model.Tokens, error) {
	// IP별 시도 제한을 가장 먼저 적용해 계정 조회와 bcrypt 연산을 무제한으로
	// 반복하는 공격 비용을 낮춥니다.
	if err := s.cache.Limit(ctx, "login", requestIP, 20, 15*time.Minute); err != nil {
		return model.Tokens{}, err
	}
	login = strings.ToLower(strings.TrimSpace(login))
	if login == "" || len(login) > 254 {
		return model.Tokens{}, model.ErrUnauthorized
	}
	current, err := s.repository.UserByLogin(ctx, login)
	if err != nil {
		return model.Tokens{}, err
	}
	if isBlocked(current) || !current.EmailVerified || !security.IsPasswordValid(password, current.PasswordHash) {
		return model.Tokens{}, model.ErrUnauthorized
	}
	return s.issueTokens(ctx, current)
}

// issueTokens는 로그인과 가입 완료가 공유하는 토큰 발급 절차입니다. Refresh Token
// 원문은 응답 쿠키용으로만 반환하고 DB에는 해시를 저장합니다. 두 토큰은 같은
// family ID를 공유해 이후 재사용이 발견되면 해당 로그인 세션 묶음을 폐기할 수 있습니다.
func (s *AuthService) issueTokens(ctx context.Context, current model.User) (model.Tokens, error) {
	// Access Token은 짧게 사용하고 Refresh Token은 DB에 해시만 저장합니다.
	// familyID를 함께 발급하면 탈취된 refresh token 재사용 시 가족 단위 폐기가 가능합니다.
	familyID := uuid.NewString()
	raw, err := security.RandomToken()
	if err != nil {
		return model.Tokens{}, err
	}
	access, err := s.tokens.Issue(current.ID, familyID, current.Role)
	if err != nil {
		return model.Tokens{}, err
	}
	expires := time.Now().Add(s.refreshTTL)
	if err = s.repository.InsertRefresh(ctx, current.ID, familyID, raw, expires); err != nil {
		return model.Tokens{}, err
	}
	return model.Tokens{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(s.tokens.TTL.Seconds()), RefreshToken: raw, RefreshExpiresAt: expires, User: current}, nil
}

// Refresh는 원문 쿠키를 저장소에 전달해 기존 토큰 폐기와 새 토큰 발급을 요청합니다.
// service에서 토큰을 미리 조회하지 않는 이유는 검사와 회전 사이의 동시 요청을
// repository 트랜잭션이 한 곳에서 직렬화해야 하기 때문입니다.
func (s *AuthService) Refresh(ctx context.Context, raw string) (model.Tokens, error) {
	// repository가 기존 토큰을 폐기하고 새 토큰을 발급하는 회전 작업을 트랜잭션으로
	// 처리합니다. 원문 길이 제한은 DB 조회 전에 비정상 입력을 차단합니다.
	if raw == "" || len(raw) > 256 {
		return model.Tokens{}, model.ErrUnauthorized
	}
	return s.repository.RotateRefresh(ctx, raw, s.tokens, s.refreshTTL)
}

// Logout은 쿠키가 없으면 이미 로그아웃된 것으로 보고 성공 처리합니다.
// 토큰이 있을 때만 해시를 기준으로 해당 Refresh Token을 폐기합니다.
func (s *AuthService) Logout(ctx context.Context, raw string) error {
	if raw == "" {
		return nil
	}
	return s.repository.RevokeToken(ctx, raw)
}

// Authenticate는 JWT 자체의 서명·만료를 확인한 뒤 PostgreSQL에서 회원 상태를
// 다시 읽습니다. 토큰 발급 뒤 계정이 차단되었거나 역할이 바뀌어도 현재 DB 상태가
// 이후 요청에 반영되도록 하기 위한 경계입니다.
func (s *AuthService) Authenticate(ctx context.Context, accessToken string) (model.User, error) {
	// HTTP middleware가 전달한 Bearer 토큰을 검증하고, 토큰의 사용자 상태를
	// 다시 조회해 차단된 계정이 기존 토큰으로 접근하지 못하게 합니다.
	claims, err := s.tokens.Parse(accessToken)
	if err != nil {
		return model.User{}, err
	}
	current, err := s.repository.UserByID(ctx, claims.Subject)
	if err != nil || isBlocked(current) {
		return model.User{}, model.ErrUnauthorized
	}
	return current, nil
}
