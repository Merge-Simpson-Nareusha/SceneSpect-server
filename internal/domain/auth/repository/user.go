package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// # 로그인 정보로 사용자 조회 기능
func (r *PostgresAuthRepository) UserByLogin(ctx context.Context, login string) (model.User, error) {
	var current model.User
	err := r.Pool.QueryRow(ctx, `SELECT id,email,username,nickname,COALESCE(avatar_url,''),display_theme,COALESCE(password_hash,''),password_version,email_verified,role,status,created_at FROM users WHERE email=$1 OR username=$1`, login).
		Scan(&current.ID, &current.Email, &current.Username, &current.Nickname, &current.AvatarURL, &current.DisplayTheme, &current.PasswordHash, &current.PasswordVersion, &current.EmailVerified, &current.Role, &current.Status, &current.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return current, model.ErrUnauthorized
	}
	return current, err
}

// # 이메일로 사용자 조회 기능
func (r *PostgresAuthRepository) UserByEmail(ctx context.Context, email string) (model.User, error) {
	var current model.User
	err := r.Pool.QueryRow(ctx, `SELECT id,email,username,nickname,COALESCE(avatar_url,''),display_theme,COALESCE(password_hash,''),password_version,email_verified,role,status,created_at FROM users WHERE email=$1`, email).
		Scan(&current.ID, &current.Email, &current.Username, &current.Nickname, &current.AvatarURL, &current.DisplayTheme, &current.PasswordHash, &current.PasswordVersion, &current.EmailVerified, &current.Role, &current.Status, &current.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return current, model.ErrUnauthorized
	}
	return current, err
}

// # ID로 사용자 조회 기능
func (r *PostgresAuthRepository) UserByID(ctx context.Context, id string) (model.User, error) {
	var current model.User
	err := r.Pool.QueryRow(ctx, `SELECT id,email,username,nickname,COALESCE(avatar_url,''),display_theme,COALESCE(password_hash,''),password_version,email_verified,role,status,created_at FROM users WHERE id=$1`, id).
		Scan(&current.ID, &current.Email, &current.Username, &current.Nickname, &current.AvatarURL, &current.DisplayTheme, &current.PasswordHash, &current.PasswordVersion, &current.EmailVerified, &current.Role, &current.Status, &current.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return current, model.ErrUnauthorized
	}
	return current, err
}

// # 사용자 닉네임 저장 기능
func (r *PostgresAuthRepository) UpdateNickname(ctx context.Context, userID, nickname string) (model.User, error) {
	var current model.User
	err := r.Pool.QueryRow(ctx, `UPDATE users SET nickname=$1,updated_at=now() WHERE id=$2 RETURNING id,email,username,nickname,COALESCE(avatar_url,''),display_theme,COALESCE(password_hash,''),password_version,email_verified,role,status,created_at`, nickname, userID).
		Scan(&current.ID, &current.Email, &current.Username, &current.Nickname, &current.AvatarURL, &current.DisplayTheme, &current.PasswordHash, &current.PasswordVersion, &current.EmailVerified, &current.Role, &current.Status, &current.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.User{}, model.ErrUnauthorized
	}
	if isUniqueViolation(err) {
		return model.User{}, model.ErrConflict
	}
	return current, err
}

// # 프로필과 화면 설정 저장 기능
func (r *PostgresAuthRepository) UpdateProfile(ctx context.Context, userID, nickname, avatarURL string) (model.User, error) {
	var current model.User
	err := r.Pool.QueryRow(ctx, `UPDATE users SET nickname=$1,avatar_url=NULLIF($2,''),updated_at=now() WHERE id=$3
		RETURNING id,email,username,nickname,COALESCE(avatar_url,''),display_theme,COALESCE(password_hash,''),password_version,email_verified,role,status,created_at`, nickname, avatarURL, userID).
		Scan(&current.ID, &current.Email, &current.Username, &current.Nickname, &current.AvatarURL, &current.DisplayTheme, &current.PasswordHash, &current.PasswordVersion, &current.EmailVerified, &current.Role, &current.Status, &current.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.User{}, model.ErrUnauthorized
	}
	if isUniqueViolation(err) {
		return model.User{}, model.ErrConflict
	}
	return current, err
}

// # 화면 테마 저장 기능
func (r *PostgresAuthRepository) UpdateDisplayTheme(ctx context.Context, userID, displayTheme string) (model.User, error) {
	var current model.User
	err := r.Pool.QueryRow(ctx, `UPDATE users SET display_theme=$1,updated_at=now() WHERE id=$2
		RETURNING id,email,username,nickname,COALESCE(avatar_url,''),display_theme,COALESCE(password_hash,''),password_version,email_verified,role,status,created_at`, displayTheme, userID).
		Scan(&current.ID, &current.Email, &current.Username, &current.Nickname, &current.AvatarURL, &current.DisplayTheme, &current.PasswordHash, &current.PasswordVersion, &current.EmailVerified, &current.Role, &current.Status, &current.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.User{}, model.ErrUnauthorized
	}
	return current, err
}

// # 이메일 중복 확인 기능
func (r *PostgresAuthRepository) EmailExists(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := r.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`, email).Scan(&exists)
	return exists, err
}

// # 약관 동의와 함께 사용자 생성 기능
func (r *PostgresAuthRepository) CreateUserWithTerms(ctx context.Context, signup model.Signup, consents []model.Consent) (model.User, error) {
	terms, accepted, err := r.validateConsents(ctx, consents)
	if err != nil {
		return model.User{}, err
	}

	// 닉네임과 로그인 아이디를 원자적으로 삽입해 동시 가입에서도 suffix 충돌을 방지합니다.
	// INSERT ... ON CONFLICT DO NOTHING 후 다음 suffix를 시도하므로 애플리케이션
	// 조회 후 삽입하는 경쟁 조건을 피할 수 있습니다.
	// 이메일은 앞선 중복 검사 뒤 다른 요청에서 선점될 수도 있으므로 DB 안에서도 확인합니다.
	// 닉네임 중복은 시도마다 suffix를 늘립니다. 유한 횟수로 제한해 이상한 DB 상태에서
	// 무한 반복하지 않고, 실제 충돌 해결은 UNIQUE 제약이 원자적으로 보장하게 합니다.
	for attempt := 1; attempt <= 1000; attempt++ {
		tx, err := r.Pool.Begin(ctx)
		if err != nil {
			return model.User{}, err
		}

		var emailExists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`, signup.Email).Scan(&emailExists); err != nil {
			_ = tx.Rollback(ctx)
			return model.User{}, err
		}
		if emailExists {
			_ = tx.Rollback(ctx)
			return model.User{}, model.ErrConflict
		}

		id := uuid.NewString()
		candidate := security.NicknameCandidate(signup.Nickname, attempt)
		var current model.User
		// 고정 아이디와 닉네임은 동일한 candidate로 시작합니다. 어느 쪽이 이미 쓰였다면
		// INSERT가 행을 만들지 않으므로 다음 suffix를 시도합니다.
		err = tx.QueryRow(ctx, `INSERT INTO users(id,email,username,nickname,password_hash,email_verified,role,status) VALUES($1,$2,$3,$4,$5,true,'USER','ACTIVE') ON CONFLICT DO NOTHING RETURNING id,email,username,nickname,COALESCE(avatar_url,''),display_theme,password_hash,password_version,email_verified,role,status,created_at`, id, signup.Email, candidate, candidate, signup.PasswordHash).
			Scan(&current.ID, &current.Email, &current.Username, &current.Nickname, &current.AvatarURL, &current.DisplayTheme, &current.PasswordHash, &current.PasswordVersion, &current.EmailVerified, &current.Role, &current.Status, &current.CreatedAt)
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

		// 사용자와 모든 현재 약관의 선택 상태를 같은 트랜잭션에서 기록합니다.
		// 하나라도 저장에 실패하면 회원 행도 rollback되어 동의 없는 계정이 남지 않습니다.
		for _, term := range terms {
			if _, err = tx.Exec(ctx, `INSERT INTO user_terms(user_id,term_id,accepted) VALUES($1,$2,$3)`, current.ID, term.ID, accepted[term.ID]); err != nil {
				_ = tx.Rollback(ctx)
				return model.User{}, err
			}
		}
		if err = tx.Commit(ctx); err != nil {
			if isUniqueViolation(err) {
				continue
			}
			return model.User{}, err
		}
		return current, nil
	}
	return model.User{}, model.ErrConflict
}
