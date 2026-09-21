// Package repository contains PostgreSQL persistence for authentication data.
package repository

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/security"
)

// AuthRepository describes the persistence operations required by auth use cases.
// Keeping this interface at the repository boundary lets the service be tested without PostgreSQL.
type AuthRepository interface {
	UserByLogin(context.Context, string) (domain.User, error)
	UserByEmail(context.Context, string) (domain.User, error)
	UserByID(context.Context, string) (domain.User, error)
	EmailExists(context.Context, string) (bool, error)
	Terms(context.Context) ([]domain.Term, error)
	CreateUserWithTerms(context.Context, domain.Signup, []domain.Consent) (domain.User, error)
	UpdateNickname(context.Context, string, string) error
	InsertRefresh(context.Context, string, string, string, time.Time) error
	RevokeToken(context.Context, string) error
	RevokeAllTokens(context.Context, string) error
	RotateRefresh(context.Context, string, security.TokenManager, time.Duration) (domain.Tokens, error)
	ResetPassword(context.Context, string, string) error
}

type PostgresAuthRepository struct{ Pool *pgxpool.Pool }

func NewPostgresAuthRepository(pool *pgxpool.Pool) *PostgresAuthRepository {
	return &PostgresAuthRepository{Pool: pool}
}

func (r *PostgresAuthRepository) UserByLogin(ctx context.Context, login string) (domain.User, error) {
	var user domain.User
	err := r.Pool.QueryRow(ctx, `SELECT id,email,username,nickname,COALESCE(password_hash,''),password_version,email_verified,role,status,created_at FROM users WHERE email=$1 OR username=$1`, login).
		Scan(&user.ID, &user.Email, &user.Username, &user.Nickname, &user.PasswordHash, &user.PasswordVersion, &user.EmailVerified, &user.Role, &user.Status, &user.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return user, domain.ErrUnauthorized
	}
	return user, err
}

func (r *PostgresAuthRepository) UserByEmail(ctx context.Context, email string) (domain.User, error) {
	var user domain.User
	err := r.Pool.QueryRow(ctx, `SELECT id,email,username,nickname,COALESCE(password_hash,''),password_version,email_verified,role,status,created_at FROM users WHERE email=$1`, email).
		Scan(&user.ID, &user.Email, &user.Username, &user.Nickname, &user.PasswordHash, &user.PasswordVersion, &user.EmailVerified, &user.Role, &user.Status, &user.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return user, domain.ErrUnauthorized
	}
	return user, err
}

func (r *PostgresAuthRepository) UserByID(ctx context.Context, id string) (domain.User, error) {
	var user domain.User
	err := r.Pool.QueryRow(ctx, `SELECT id,email,username,nickname,COALESCE(password_hash,''),password_version,email_verified,role,status,created_at FROM users WHERE id=$1`, id).
		Scan(&user.ID, &user.Email, &user.Username, &user.Nickname, &user.PasswordHash, &user.PasswordVersion, &user.EmailVerified, &user.Role, &user.Status, &user.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return user, domain.ErrUnauthorized
	}
	return user, err
}

func (r *PostgresAuthRepository) EmailExists(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := r.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`, email).Scan(&exists)
	return exists, err
}

func (r *PostgresAuthRepository) Terms(ctx context.Context) ([]domain.Term, error) {
	rows, err := r.Pool.Query(ctx, `SELECT id,code,version,title,content,required FROM terms WHERE active ORDER BY code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var terms []domain.Term
	for rows.Next() {
		var term domain.Term
		if err := rows.Scan(&term.ID, &term.Code, &term.Version, &term.Title, &term.Content, &term.Required); err != nil {
			return nil, err
		}
		terms = append(terms, term)
	}
	return terms, rows.Err()
}

func (r *PostgresAuthRepository) CreateUserWithTerms(ctx context.Context, signup domain.Signup, consents []domain.Consent) (domain.User, error) {
	terms, err := r.Terms(ctx)
	if err != nil {
		return domain.User{}, err
	}

	accepted := make(map[string]bool, len(consents))
	for _, consent := range consents {
		if _, exists := accepted[consent.TermID]; exists {
			return domain.User{}, domain.ErrInvalid
		}
		accepted[consent.TermID] = consent.Accepted
	}
	for _, term := range terms {
		if term.Required && !accepted[term.ID] {
			return domain.User{}, domain.ErrTerms
		}
	}
	for _, consent := range consents {
		found := false
		for _, term := range terms {
			if term.ID == consent.TermID {
				found = true
				break
			}
		}
		if !found {
			return domain.User{}, domain.ErrInvalid
		}
	}

	// 닉네임과 로그인 아이디를 원자적으로 삽입해 동시 가입에서도 suffix 충돌을 방지합니다.
	for attempt := 1; attempt <= 1000; attempt++ {
		tx, err := r.Pool.Begin(ctx)
		if err != nil {
			return domain.User{}, err
		}

		var emailExists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`, signup.Email).Scan(&emailExists); err != nil {
			_ = tx.Rollback(ctx)
			return domain.User{}, err
		}
		if emailExists {
			_ = tx.Rollback(ctx)
			return domain.User{}, domain.ErrConflict
		}

		id := uuid.NewString()
		candidate := security.NicknameCandidate(signup.Nickname, attempt)
		var user domain.User
		err = tx.QueryRow(ctx, `INSERT INTO users(id,email,username,nickname,password_hash,email_verified,role,status) VALUES($1,$2,$3,$4,$5,true,'USER','ACTIVE') ON CONFLICT DO NOTHING RETURNING id,email,username,nickname,password_hash,password_version,email_verified,role,status,created_at`, id, signup.Email, candidate, candidate, signup.PasswordHash).
			Scan(&user.ID, &user.Email, &user.Username, &user.Nickname, &user.PasswordHash, &user.PasswordVersion, &user.EmailVerified, &user.Role, &user.Status, &user.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			_ = tx.Rollback(ctx)
			continue
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			if isUniqueViolation(err) {
				continue
			}
			return domain.User{}, err
		}

		for _, term := range terms {
			if _, err = tx.Exec(ctx, `INSERT INTO user_terms(user_id,term_id,accepted) VALUES($1,$2,$3)`, user.ID, term.ID, accepted[term.ID]); err != nil {
				_ = tx.Rollback(ctx)
				return domain.User{}, err
			}
		}
		if err = tx.Commit(ctx); err != nil {
			if isUniqueViolation(err) {
				continue
			}
			return domain.User{}, err
		}
		return user, nil
	}
	return domain.User{}, domain.ErrConflict
}

func (r *PostgresAuthRepository) UpdateNickname(ctx context.Context, userID, nickname string) error {
	_, err := r.Pool.Exec(ctx, `UPDATE users SET nickname=$1,updated_at=now() WHERE id=$2`, nickname, userID)
	if isUniqueViolation(err) {
		return domain.ErrConflict
	}
	return err
}

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

func (r *PostgresAuthRepository) RotateRefresh(ctx context.Context, raw string, tokenManager security.TokenManager, refreshTTL time.Duration) (domain.Tokens, error) {
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return domain.Tokens{}, err
	}
	defer tx.Rollback(ctx)

	var id, userID, familyID, storedHash, role string
	var expires, revoked *time.Time
	err = tx.QueryRow(ctx, `SELECT r.id,r.user_id,r.family_id,r.token_hash,r.expires_at,r.revoked_at,u.role FROM refresh_tokens r JOIN users u ON u.id=r.user_id WHERE r.token_hash=$1 FOR UPDATE`, security.TokenHash(raw)).
		Scan(&id, &userID, &familyID, &storedHash, &expires, &revoked, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Tokens{}, domain.ErrUnauthorized
	}
	if err != nil {
		return domain.Tokens{}, err
	}
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(security.TokenHash(raw))) != 1 || expires.Before(time.Now()) || revoked != nil {
		_, _ = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE family_id=$1`, familyID)
		_ = tx.Commit(ctx)
		return domain.Tokens{}, domain.ErrUnauthorized
	}
	if _, err = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=now() WHERE id=$1`, id); err != nil {
		return domain.Tokens{}, err
	}

	newRaw, err := security.RandomToken()
	if err != nil {
		return domain.Tokens{}, err
	}
	newExpires := time.Now().Add(refreshTTL)
	if _, err = tx.Exec(ctx, `INSERT INTO refresh_tokens(id,user_id,family_id,token_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, uuid.NewString(), userID, familyID, security.TokenHash(newRaw), newExpires); err != nil {
		return domain.Tokens{}, err
	}
	access, err := tokenManager.Issue(userID, familyID, role)
	if err != nil {
		return domain.Tokens{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return domain.Tokens{}, err
	}
	return domain.Tokens{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(tokenManager.TTL.Seconds()), RefreshToken: newRaw, RefreshExpiresAt: newExpires}, nil
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

func isUniqueViolation(err error) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505"
}
