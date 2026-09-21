package auth

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/user"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

func (r *PostgresAuthRepository) UserByLogin(ctx context.Context, login string) (user.User, error) {
	var current user.User
	err := r.Pool.QueryRow(ctx, `SELECT id,email,username,nickname,COALESCE(password_hash,''),password_version,email_verified,role,status,created_at FROM users WHERE email=$1 OR username=$1`, login).
		Scan(&current.ID, &current.Email, &current.Username, &current.Nickname, &current.PasswordHash, &current.PasswordVersion, &current.EmailVerified, &current.Role, &current.Status, &current.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return current, ErrUnauthorized
	}
	return current, err
}

func (r *PostgresAuthRepository) UserByEmail(ctx context.Context, email string) (user.User, error) {
	var current user.User
	err := r.Pool.QueryRow(ctx, `SELECT id,email,username,nickname,COALESCE(password_hash,''),password_version,email_verified,role,status,created_at FROM users WHERE email=$1`, email).
		Scan(&current.ID, &current.Email, &current.Username, &current.Nickname, &current.PasswordHash, &current.PasswordVersion, &current.EmailVerified, &current.Role, &current.Status, &current.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return current, ErrUnauthorized
	}
	return current, err
}

func (r *PostgresAuthRepository) UserByID(ctx context.Context, id string) (user.User, error) {
	var current user.User
	err := r.Pool.QueryRow(ctx, `SELECT id,email,username,nickname,COALESCE(password_hash,''),password_version,email_verified,role,status,created_at FROM users WHERE id=$1`, id).
		Scan(&current.ID, &current.Email, &current.Username, &current.Nickname, &current.PasswordHash, &current.PasswordVersion, &current.EmailVerified, &current.Role, &current.Status, &current.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return current, ErrUnauthorized
	}
	return current, err
}

func (r *PostgresAuthRepository) EmailExists(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := r.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`, email).Scan(&exists)
	return exists, err
}

func (r *PostgresAuthRepository) CreateUserWithTerms(ctx context.Context, signup Signup, consents []Consent) (user.User, error) {
	terms, err := r.Terms(ctx)
	if err != nil {
		return user.User{}, err
	}

	accepted := make(map[string]bool, len(consents))
	for _, consent := range consents {
		if _, exists := accepted[consent.TermID]; exists {
			return user.User{}, ErrInvalid
		}
		accepted[consent.TermID] = consent.Accepted
	}
	for _, term := range terms {
		if term.Required && !accepted[term.ID] {
			return user.User{}, ErrTerms
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
			return user.User{}, ErrInvalid
		}
	}

	// 닉네임과 로그인 아이디를 원자적으로 삽입해 동시 가입에서도 suffix 충돌을 방지합니다.
	for attempt := 1; attempt <= 1000; attempt++ {
		tx, err := r.Pool.Begin(ctx)
		if err != nil {
			return user.User{}, err
		}

		var emailExists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`, signup.Email).Scan(&emailExists); err != nil {
			_ = tx.Rollback(ctx)
			return user.User{}, err
		}
		if emailExists {
			_ = tx.Rollback(ctx)
			return user.User{}, ErrConflict
		}

		id := uuid.NewString()
		candidate := security.NicknameCandidate(signup.Nickname, attempt)
		var current user.User
		err = tx.QueryRow(ctx, `INSERT INTO users(id,email,username,nickname,password_hash,email_verified,role,status) VALUES($1,$2,$3,$4,$5,true,'USER','ACTIVE') ON CONFLICT DO NOTHING RETURNING id,email,username,nickname,password_hash,password_version,email_verified,role,status,created_at`, id, signup.Email, candidate, candidate, signup.PasswordHash).
			Scan(&current.ID, &current.Email, &current.Username, &current.Nickname, &current.PasswordHash, &current.PasswordVersion, &current.EmailVerified, &current.Role, &current.Status, &current.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			_ = tx.Rollback(ctx)
			continue
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			if isUniqueViolation(err) {
				continue
			}
			return user.User{}, err
		}

		for _, term := range terms {
			if _, err = tx.Exec(ctx, `INSERT INTO user_terms(user_id,term_id,accepted) VALUES($1,$2,$3)`, current.ID, term.ID, accepted[term.ID]); err != nil {
				_ = tx.Rollback(ctx)
				return user.User{}, err
			}
		}
		if err = tx.Commit(ctx); err != nil {
			if isUniqueViolation(err) {
				continue
			}
			return user.User{}, err
		}
		return current, nil
	}
	return user.User{}, ErrConflict
}

func (r *PostgresAuthRepository) UpdateNickname(ctx context.Context, userID, nickname string) error {
	_, err := r.Pool.Exec(ctx, `UPDATE users SET nickname=$1,updated_at=now() WHERE id=$2`, nickname, userID)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}
