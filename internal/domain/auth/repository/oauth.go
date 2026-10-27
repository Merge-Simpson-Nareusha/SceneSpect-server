package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

func (r *PostgresAuthRepository) UserByOAuth(ctx context.Context, provider, providerUserID string) (model.User, error) {
	var current model.User
	err := r.Pool.QueryRow(ctx, `SELECT u.id,u.email,u.username,u.nickname,COALESCE(u.avatar_url,''),u.display_theme,
		COALESCE(u.password_hash,''),u.password_version,u.email_verified,u.role,u.status,u.created_at
		FROM oauth_accounts oa JOIN users u ON u.id=oa.user_id WHERE oa.provider=$1 AND oa.provider_user_id=$2`, provider, providerUserID).
		Scan(&current.ID, &current.Email, &current.Username, &current.Nickname, &current.AvatarURL, &current.DisplayTheme,
			&current.PasswordHash, &current.PasswordVersion, &current.EmailVerified, &current.Role, &current.Status, &current.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.User{}, model.ErrUnauthorized
	}
	return current, err
}

func (r *PostgresAuthRepository) LinkOAuthAccount(ctx context.Context, userID, provider, providerUserID string) error {
	tag, err := r.Pool.Exec(ctx, `INSERT INTO oauth_accounts(provider,provider_user_id,user_id) VALUES($1,$2,$3)
		ON CONFLICT(provider,provider_user_id) DO UPDATE SET user_id=EXCLUDED.user_id
		WHERE oauth_accounts.user_id=EXCLUDED.user_id`, provider, providerUserID, userID)
	if err != nil {
		if isUniqueViolation(err) {
			return model.ErrConflict
		}
		return err
	}
	if tag.RowsAffected() != 1 {
		return model.ErrConflict
	}
	return nil
}

func (r *PostgresAuthRepository) CreateOAuthUserWithTerms(ctx context.Context, provider, providerUserID, email, nickname, avatarURL string, consents []model.Consent) (model.User, error) {
	terms, accepted, err := r.validateConsents(ctx, consents)
	if err != nil {
		return model.User{}, err
	}
	for attempt := 1; attempt <= 1000; attempt++ {
		tx, err := r.Pool.Begin(ctx)
		if err != nil {
			return model.User{}, err
		}

		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oauth_accounts WHERE provider=$1 AND provider_user_id=$2)`, provider, providerUserID).Scan(&exists); err != nil {
			_ = tx.Rollback(ctx)
			return model.User{}, err
		}
		if exists {
			_ = tx.Rollback(ctx)
			return model.User{}, model.ErrConflict
		}
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`, email).Scan(&exists); err != nil {
			_ = tx.Rollback(ctx)
			return model.User{}, err
		}
		if exists {
			_ = tx.Rollback(ctx)
			return model.User{}, model.ErrConflict
		}

		id := uuid.NewString()
		candidate := security.NicknameCandidate(nickname, attempt)
		var current model.User
		err = tx.QueryRow(ctx, `INSERT INTO users(id,email,username,nickname,email_verified,avatar_url,role,status)
			VALUES($1,$2,$3,$3,true,NULLIF($4,''),'USER','ACTIVE') ON CONFLICT DO NOTHING
			RETURNING id,email,username,nickname,COALESCE(avatar_url,''),display_theme,COALESCE(password_hash,''),password_version,email_verified,role,status,created_at`,
			id, email, candidate, avatarURL).
			Scan(&current.ID, &current.Email, &current.Username, &current.Nickname, &current.AvatarURL, &current.DisplayTheme,
				&current.PasswordHash, &current.PasswordVersion, &current.EmailVerified, &current.Role, &current.Status, &current.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			_ = tx.Rollback(ctx)
			continue
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			if isUniqueViolation(err) {
				continue
			}
			return model.User{}, err
		}

		for _, term := range terms {
			if _, err = tx.Exec(ctx, `INSERT INTO user_terms(user_id,term_id,accepted) VALUES($1,$2,$3)`, current.ID, term.ID, accepted[term.ID]); err != nil {
				_ = tx.Rollback(ctx)
				return model.User{}, err
			}
		}
		if _, err = tx.Exec(ctx, `INSERT INTO oauth_accounts(provider,provider_user_id,user_id) VALUES($1,$2,$3)`, provider, providerUserID, current.ID); err != nil {
			_ = tx.Rollback(ctx)
			if isUniqueViolation(err) {
				return model.User{}, model.ErrConflict
			}
			return model.User{}, err
		}
		if err = tx.Commit(ctx); err != nil {
			if isUniqueViolation(err) {
				return model.User{}, model.ErrConflict
			}
			return model.User{}, err
		}
		return current, nil
	}
	return model.User{}, model.ErrConflict
}

func (r *PostgresAuthRepository) validateConsents(ctx context.Context, consents []model.Consent) ([]model.Term, map[string]bool, error) {
	terms, err := r.Terms(ctx)
	if err != nil {
		return nil, nil, err
	}
	accepted := make(map[string]bool, len(consents))
	for _, consent := range consents {
		if _, exists := accepted[consent.TermID]; exists {
			return nil, nil, model.ErrInvalid
		}
		accepted[consent.TermID] = consent.Accepted
	}
	validIDs := make(map[string]struct{}, len(terms))
	for _, term := range terms {
		validIDs[term.ID] = struct{}{}
		if term.Required && !accepted[term.ID] {
			return nil, nil, model.ErrTerms
		}
	}
	for _, consent := range consents {
		if _, exists := validIDs[consent.TermID]; !exists {
			return nil, nil, model.ErrInvalid
		}
	}
	return terms, accepted, nil
}
