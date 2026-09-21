// Package cache contains Redis-backed, TTL-bound authentication state.
package cache

import (
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/security"
)

const (
	SignupTTL = 30 * time.Minute
	CodeTTL   = 5 * time.Minute
	ResetTTL  = 15 * time.Minute
)

type Ephemeral struct{ Client *redis.Client }

func signupKey(id string) string { return "signup:session:" + security.TokenHash(id) }
func verifyKey(id string) string { return "email:verify:" + security.TokenHash(id) }
