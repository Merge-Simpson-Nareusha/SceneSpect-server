// Package database owns PostgreSQL and Redis connection adapters.
package database

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

const (
	SignupTTL = 30 * time.Minute
	CodeTTL   = 5 * time.Minute
	ResetTTL  = 15 * time.Minute
)

type Ephemeral struct{ Client *redis.Client }

// NewRedis creates and verifies the Redis client before the HTTP server starts.
func NewRedis(ctx context.Context, redisURL string) (*redis.Client, error) {
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(options)
	if err = client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}

type SignupData struct {
	Email, Nickname, PasswordHash string
}

func signupKey(id string) string { return "signup:session:" + security.TokenHash(id) }
func verifyKey(id string) string { return "email:verify:" + security.TokenHash(id) }
