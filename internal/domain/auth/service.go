// Package auth contains authentication use cases and keeps transport details out of business logic.
package auth

import (
	"context"
	"time"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/database"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/mailer"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// SignupCache keeps unfinished signup and reset flows in Redis with TTLs.
type SignupCache interface {
	CreateSignup(context.Context, string, string, string) error
	SetPassword(context.Context, string, string) error
	Signup(context.Context, string, string) (database.SignupData, error)
	DeleteSignup(context.Context, string) error
	SaveCode(context.Context, string, string, string) error
	VerifyCode(context.Context, string, string) error
	Limit(context.Context, string, string, int, time.Duration) error
	SaveReset(context.Context, string, string, int64) error
	ConsumeReset(context.Context, string) (database.ResetState, error)
}

type AuthService struct {
	repository AuthRepository
	cache      SignupCache
	mailer     mailer.Sender
	tokens     security.TokenManager
	codeKey    []byte
	bcryptCost int
	refreshTTL time.Duration
}

func NewAuthService(repo AuthRepository, ephemeral SignupCache, sender mailer.Sender, tokens security.TokenManager, codeKey []byte, bcryptCost int, refreshTTL time.Duration) *AuthService {
	return &AuthService{
		repository: repo,
		cache:      ephemeral,
		mailer:     sender,
		tokens:     tokens,
		codeKey:    codeKey,
		bcryptCost: bcryptCost,
		refreshTTL: refreshTTL,
	}
}

func (s *AuthService) Terms(ctx context.Context) ([]Term, error) {
	return s.repository.Terms(ctx)
}
