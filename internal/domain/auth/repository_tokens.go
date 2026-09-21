package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

func (r *PostgresAuthRepository) InsertRefresh(ctx context.Context, userID, familyID, raw string, expires time.Time) error {
	_, err := r.Pool.Exec(ctx, `INSERT INTO refresh_tokens(id,user_id,family_id,token_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, uuid.NewString(), userID, familyID, security.TokenHash(raw), expires)
	return err
}

func (r *PostgresAuthRepository) RevokeToken(ctx context.Context, raw string) error {
	_, err := r.Pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE token_hash=$1`, security.TokenHash(raw))
	return err
}

func (r *PostgresAuthRepository) RevokeAllTokens(ctx context.Context, userID string) error {
	_, err := r.Pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE user_id=$1 AND revoked_at IS NULL`, userID)
	return err
}

func (r *PostgresAuthRepository) RotateRefresh(ctx context.Context, raw string, tokenManager security.TokenManager, refreshTTL time.Duration) (Tokens, error) {
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return Tokens{}, err
	}
	defer tx.Rollback(ctx)

	var id, userID, familyID, storedHash, role string
	var expires, revoked *time.Time
	err = tx.QueryRow(ctx, `SELECT r.id,r.user_id,r.family_id,r.token_hash,r.expires_at,r.revoked_at,u.role FROM refresh_tokens r JOIN users u ON u.id=r.user_id WHERE r.token_hash=$1 FOR UPDATE`, security.TokenHash(raw)).
		Scan(&id, &userID, &familyID, &storedHash, &expires, &revoked, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tokens{}, ErrUnauthorized
	}
	if err != nil {
		return Tokens{}, err
	}
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(security.TokenHash(raw))) != 1 || expires.Before(time.Now()) || revoked != nil {
		_, _ = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE family_id=$1`, familyID)
		_ = tx.Commit(ctx)
		return Tokens{}, ErrUnauthorized
	}
	if _, err = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=now() WHERE id=$1`, id); err != nil {
		return Tokens{}, err
	}

	newRaw, err := security.RandomToken()
	if err != nil {
		return Tokens{}, err
	}
	newExpires := time.Now().Add(refreshTTL)
	if _, err = tx.Exec(ctx, `INSERT INTO refresh_tokens(id,user_id,family_id,token_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, uuid.NewString(), userID, familyID, security.TokenHash(newRaw), newExpires); err != nil {
		return Tokens{}, err
	}
	access, err := tokenManager.Issue(userID, familyID, role)
	if err != nil {
		return Tokens{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(tokenManager.TTL.Seconds()), RefreshToken: newRaw, RefreshExpiresAt: newExpires}, nil
}

func (r *PostgresAuthRepository) ResetPassword(ctx context.Context, userID, passwordHash string) error {
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
