package redis

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

const (
	OAuthStateTTL  = 10 * time.Minute
	OAuthSignupTTL = 20 * time.Minute
)

type OAuthState struct {
	Provider string `json:"provider"`
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
	UserID   string `json:"userId,omitempty"`
}

type OAuthSignup struct {
	Provider        string `json:"provider"`
	Subject         string `json:"subject"`
	Email           string `json:"email"`
	EmailVerified   bool   `json:"emailVerified"`
	Nickname        string `json:"nickname"`
	AvatarURL       string `json:"avatarUrl"`
	SignupSessionID string `json:"signupSessionId,omitempty"`
}

func (e Ephemeral) SaveOAuthState(ctx context.Context, state string, value OAuthState) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return e.Client.Set(ctx, oauthStateKey(state), encoded, OAuthStateTTL).Err()
}

// ConsumeOAuthState uses GETDEL so two concurrent callbacks cannot both exchange
// the same authorization code and attach it to separate sessions.
func (e Ephemeral) ConsumeOAuthState(ctx context.Context, state string) (OAuthState, error) {
	encoded, err := e.Client.GetDel(ctx, oauthStateKey(state)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return OAuthState{}, response.ErrState
	}
	if err != nil {
		return OAuthState{}, err
	}
	var value OAuthState
	if err = json.Unmarshal(encoded, &value); err != nil {
		return OAuthState{}, response.ErrState
	}
	return value, nil
}

func (e Ephemeral) SaveOAuthSignup(ctx context.Context, session string, value OAuthSignup) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return e.Client.Set(ctx, oauthSignupKey(session), encoded, OAuthSignupTTL).Err()
}

func (e Ephemeral) OAuthSignup(ctx context.Context, session string) (OAuthSignup, error) {
	encoded, err := e.Client.Get(ctx, oauthSignupKey(session)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return OAuthSignup{}, response.ErrState
	}
	if err != nil {
		return OAuthSignup{}, err
	}
	var value OAuthSignup
	if err = json.Unmarshal(encoded, &value); err != nil {
		return OAuthSignup{}, response.ErrState
	}
	return value, nil
}

func (e Ephemeral) DeleteOAuthSignup(ctx context.Context, session string) error {
	return e.Client.Del(ctx, oauthSignupKey(session)).Err()
}

func oauthStateKey(state string) string    { return "oauth:state:" + security.TokenHash(state) }
func oauthSignupKey(session string) string { return "oauth:signup:" + security.TokenHash(session) }
