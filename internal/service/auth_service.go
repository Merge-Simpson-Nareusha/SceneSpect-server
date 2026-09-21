// Package service contains authentication use cases and keeps transport details out of business logic.
package service

import (
	"context"
	"time"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/cache"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/mailer"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/repository"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/security"
)

type SignupStartResult struct {
	SignupSessionID string
	Email           string
	Nickname        string
	ExpiresIn       int64
}

type VerificationResult struct {
	ExpiresIn   int64
	ResendAfter int64
}

type AccountLookupResult struct {
	Email    string
	Username string
}

// SignupCache keeps unfinished signup and reset flows in Redis with TTLs.
type SignupCache interface {
	CreateSignup(context.Context, string, string, string) error
	SetPassword(context.Context, string, string) error
	Signup(context.Context, string, string) (domain.Signup, error)
	DeleteSignup(context.Context, string) error
	SaveCode(context.Context, string, string, string) error
	VerifyCode(context.Context, string, string) error
	Limit(context.Context, string, string, int, time.Duration) error
	SaveReset(context.Context, string, domain.User) error
	ConsumeReset(context.Context, string) (cache.ResetState, error)
}

type AuthService struct {
	repository repository.AuthRepository
	cache      SignupCache
	mailer     mailer.Sender
	tokens     security.TokenManager
	codeKey    []byte
	bcryptCost int
	refreshTTL time.Duration
}

func NewAuthService(repo repository.AuthRepository, ephemeral SignupCache, sender mailer.Sender, tokens security.TokenManager, codeKey []byte, bcryptCost int, refreshTTL time.Duration) *AuthService {
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

func (s *AuthService) Terms(ctx context.Context) ([]domain.Term, error) {
	return s.repository.Terms(ctx)
}
