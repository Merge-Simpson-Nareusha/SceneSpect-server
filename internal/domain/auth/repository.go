// Package auth contains PostgreSQL persistence for authentication data.
package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/user"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// AuthRepository describes the persistence operations required by auth use cases.
// Keeping this interface at the repository boundary lets the service be tested without PostgreSQL.
type AuthRepository interface {
	UserByLogin(context.Context, string) (user.User, error)
	UserByEmail(context.Context, string) (user.User, error)
	UserByID(context.Context, string) (user.User, error)
	EmailExists(context.Context, string) (bool, error)
	Terms(context.Context) ([]Term, error)
	CreateUserWithTerms(context.Context, Signup, []Consent) (user.User, error)
	UpdateNickname(context.Context, string, string) error
	InsertRefresh(context.Context, string, string, string, time.Time) error
	RevokeToken(context.Context, string) error
	RevokeAllTokens(context.Context, string) error
	RotateRefresh(context.Context, string, security.TokenManager, time.Duration) (Tokens, error)
	ResetPassword(context.Context, string, string) error
}

type PostgresAuthRepository struct{ Pool *pgxpool.Pool }

func NewPostgresAuthRepository(pool *pgxpool.Pool) *PostgresAuthRepository {
	return &PostgresAuthRepository{Pool: pool}
}
