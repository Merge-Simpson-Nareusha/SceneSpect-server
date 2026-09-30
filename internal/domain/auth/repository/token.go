package repository

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// InsertRefresh는 원문 대신 해시한 Refresh Token과 만료 정보를 저장합니다.
func (r *PostgresAuthRepository) InsertRefresh(ctx context.Context, userID, familyID, raw string, expires time.Time) error {
	// raw는 절대 저장하지 않고 SHA-256 해시만 저장합니다. DB가 읽혀도 쿠키 원문을
	// 바로 사용할 수 없도록 하는 핵심 경계입니다.
	_, err := r.Pool.Exec(ctx, `INSERT INTO refresh_tokens(id,user_id,family_id,token_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, uuid.NewString(), userID, familyID, security.TokenHash(raw), expires)
	return err
}

// RevokeToken은 해시로 Refresh Token을 찾아 최초 폐기 시각을 기록합니다.
func (r *PostgresAuthRepository) RevokeToken(ctx context.Context, raw string) error {
	_, err := r.Pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE token_hash=$1`, security.TokenHash(raw))
	return err
}

// RevokeAllTokens는 비밀번호 변경 뒤 해당 계정의 모든 활성 Refresh Token을 폐기합니다.
func (r *PostgresAuthRepository) RevokeAllTokens(ctx context.Context, userID string) error {
	_, err := r.Pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE user_id=$1 AND revoked_at IS NULL`, userID)
	return err
}

// RotateRefresh는 기존 토큰을 폐기하고 새 토큰을 발급하는 과정을 한 트랜잭션으로 처리합니다.
func (r *PostgresAuthRepository) RotateRefresh(ctx context.Context, raw string, tokenManager security.TokenManager, refreshTTL time.Duration) (model.Tokens, error) {
	// FOR UPDATE가 같은 토큰을 동시에 재발급하는 요청을 직렬화합니다.
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return model.Tokens{}, err
	}
	defer tx.Rollback(ctx)

	var id, userID, familyID, storedHash, role string
	var expires, revoked *time.Time
	err = tx.QueryRow(ctx, `SELECT r.id,r.user_id,r.family_id,r.token_hash,r.expires_at,r.revoked_at,u.role FROM refresh_tokens r JOIN users u ON u.id=r.user_id WHERE r.token_hash=$1 FOR UPDATE`, security.TokenHash(raw)).
		Scan(&id, &userID, &familyID, &storedHash, &expires, &revoked, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Tokens{}, model.ErrUnauthorized
	}
	if err != nil {
		return model.Tokens{}, err
	}
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(security.TokenHash(raw))) != 1 || expires.Before(time.Now()) || revoked != nil {
		// 만료되었거나 이미 폐기된 토큰이 제출되면 family 전체를 폐기해
		// 같은 세션의 다른 Refresh Token도 함께 무효화합니다. 이 거부 경로에서는 폐기 UPDATE를
		// 보존해야 하므로 일반적인 defer Rollback 전에 명시적으로 커밋합니다.
		_, _ = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE family_id=$1`, familyID)
		_ = tx.Commit(ctx)
		return model.Tokens{}, model.ErrUnauthorized
	}
	if _, err = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=now() WHERE id=$1`, id); err != nil {
		return model.Tokens{}, err
	}

	newRaw, err := security.RandomToken()
	if err != nil {
		return model.Tokens{}, err
	}
	newExpires := time.Now().Add(refreshTTL)
	// DB에는 새 원문이 아니라 해시만 넣고, 원문은 commit 뒤 handler에 반환합니다.
	if _, err = tx.Exec(ctx, `INSERT INTO refresh_tokens(id,user_id,family_id,token_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, uuid.NewString(), userID, familyID, security.TokenHash(newRaw), newExpires); err != nil {
		return model.Tokens{}, err
	}
	access, err := tokenManager.Issue(userID, familyID, role)
	if err != nil {
		return model.Tokens{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return model.Tokens{}, err
	}
	return model.Tokens{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(tokenManager.TTL.Seconds()), RefreshToken: newRaw, RefreshExpiresAt: newExpires}, nil
}

// ResetPassword는 비밀번호를 바꾸고 활성 Refresh Token을 한 트랜잭션에서 폐기합니다.
func (r *PostgresAuthRepository) ResetPassword(ctx context.Context, userID, passwordHash string) error {
	// 비밀번호 변경과 기존 refresh token 폐기를 같은 트랜잭션으로 묶어,
	// 변경은 되었지만 이전 세션이 살아남는 중간 상태를 방지합니다.
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `UPDATE users SET password_hash=$1,password_version=password_version+1,updated_at=now() WHERE id=$2`, passwordHash, userID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE user_id=$1 AND revoked_at IS NULL`, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
