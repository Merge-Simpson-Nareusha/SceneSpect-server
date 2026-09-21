package user

import "context"

// Repository documents persistence required by user use cases. The current
// PostgreSQL adapter is shared with auth and implements these operations there
// so one transaction boundary remains responsible for the users table.
type Repository interface {
	UserByID(context.Context, string) (User, error)
	UpdateNickname(context.Context, string, string) error
}
