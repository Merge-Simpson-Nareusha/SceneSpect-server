// Package auth contains the authentication domain model and use cases.
package auth

import (
	"time"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/user"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

// Error values are aliases to the transport-neutral errors owned by the global
// response package. Keeping one error identity lets every adapter use errors.Is.
var (
	ErrInvalid      = response.ErrInvalid
	ErrUnauthorized = response.ErrUnauthorized
	ErrConflict     = response.ErrConflict
	ErrTerms        = response.ErrTerms
	ErrState        = response.ErrState
	ErrCode         = response.ErrCode
	ErrRateLimit    = response.ErrRateLimit
)

type Consent struct {
	TermID   string `json:"termId"`
	Accepted bool   `json:"accepted"`
}

type Signup struct {
	Email, Nickname, PasswordHash string
}

type Term struct {
	ID       string `json:"id"`
	Code     string `json:"code"`
	Version  string `json:"version"`
	Title    string `json:"title"`
	Content  string `json:"content"`
	Required bool   `json:"required"`
}

type Tokens struct {
	AccessToken      string    `json:"accessToken"`
	TokenType        string    `json:"tokenType"`
	ExpiresIn        int64     `json:"expiresIn"`
	User             user.User `json:"user"`
	RefreshToken     string    `json:"-"`
	RefreshExpiresAt time.Time `json:"-"`
}
