// Package repository contains PostgreSQL persistence for authentication data.
package repository

import (
	"context"
	"time"

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
