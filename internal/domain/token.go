package domain

import "time"

type Tokens struct {
	AccessToken      string    `json:"accessToken"`
	TokenType        string    `json:"tokenType"`
	ExpiresIn        int64     `json:"expiresIn"`
	User             User      `json:"user"`
	RefreshToken     string    `json:"-"`
	RefreshExpiresAt time.Time `json:"-"`
}
