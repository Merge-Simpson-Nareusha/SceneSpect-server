package user

import "context"

// Service exposes user-only operations to the user transport layer.
type Service interface {
	UpdateNickname(context.Context, string, string) (User, error)
}
