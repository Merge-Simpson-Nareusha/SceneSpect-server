package security

import "time"

// Principal is the authenticated identity shared by middleware and domains.
// It lives in the global security layer so transport packages do not import
// the user domain back into authentication middleware.
type Principal struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	Username        string    `json:"username"`
	Nickname        string    `json:"nickname"`
	Role            string    `json:"role"`
	Status          string    `json:"status"`
	EmailVerified   bool      `json:"emailVerified"`
	CreatedAt       time.Time `json:"createdAt"`
	PasswordHash    string    `json:"-"`
	PasswordVersion int64     `json:"-"`
}
