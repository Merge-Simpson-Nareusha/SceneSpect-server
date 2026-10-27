package model

import (
	"time"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

var (
	ErrInvalid   = response.ErrInvalid
	ErrConflict  = response.ErrConflict
	ErrForbidden = response.ErrForbidden
	ErrNotFound  = response.ErrNotFound
)

type AccessLevel string
type Visibility string

const (
	ViewerAccess  AccessLevel = "VIEWER"
	EditorAccess  AccessLevel = "EDITOR"
	ManagerAccess AccessLevel = "MANAGER"
)

const (
	TeamVisibility     Visibility = "TEAM"
	SelectedVisibility Visibility = "SELECTED"
)

type RequestStatus string

const (
	PendingStatus  RequestStatus = "PENDING"
	AcceptedStatus RequestStatus = "ACCEPTED"
	RejectedStatus RequestStatus = "REJECTED"
)

type Project struct {
	ID           string      `json:"id"`
	TeamID       string      `json:"teamId"`
	Name         string      `json:"name"`
	Description  string      `json:"description"`
	ThumbnailURL *string     `json:"thumbnailUrl,omitempty"`
	Visibility   Visibility  `json:"visibility"`
	CreatedBy    string      `json:"createdBy"`
	AccessLevel  AccessLevel `json:"accessLevel"`
	CreatedAt    time.Time   `json:"createdAt"`
	UpdatedAt    time.Time   `json:"updatedAt"`
}

type CreateProject struct {
	Name         string     `json:"name" binding:"required"`
	Description  string     `json:"description"`
	ThumbnailURL *string    `json:"thumbnailUrl"`
	Visibility   Visibility `json:"visibility"`
}

type UpdateProject struct {
	Name         string     `json:"name" binding:"required"`
	Description  string     `json:"description"`
	ThumbnailURL *string    `json:"thumbnailUrl"`
	Visibility   Visibility `json:"visibility"`
}

type AccessRequest struct {
	ID          string        `json:"id"`
	ProjectID   string        `json:"projectId"`
	UserID      string        `json:"userId"`
	Nickname    string        `json:"nickname,omitempty"`
	AccessLevel AccessLevel   `json:"accessLevel"`
	Message     string        `json:"message"`
	Status      RequestStatus `json:"status"`
	CreatedAt   time.Time     `json:"createdAt"`
}

type DeleteRequest struct {
	ID        string        `json:"id"`
	ProjectID string        `json:"projectId"`
	UserID    string        `json:"userId"`
	Nickname  string        `json:"nickname,omitempty"`
	Message   string        `json:"message"`
	Status    RequestStatus `json:"status"`
	CreatedAt time.Time     `json:"createdAt"`
}

type ReviewRequest struct {
	Accept bool `json:"accept"`
}

type GrantAccess struct {
	AccessLevel AccessLevel `json:"accessLevel" binding:"required"`
}

type RequestAccess struct {
	AccessLevel AccessLevel `json:"accessLevel"`
	Message     string      `json:"message"`
}

type RequestDeletion struct {
	Message string `json:"message"`
}

type ProjectMember struct {
	UserID      string      `json:"userId"`
	Nickname    string      `json:"nickname"`
	AvatarURL   string      `json:"avatarUrl,omitempty"`
	TeamRole    string      `json:"teamRole"`
	AccessLevel AccessLevel `json:"accessLevel,omitempty"`
	GrantedAt   *time.Time  `json:"grantedAt,omitempty"`
}
