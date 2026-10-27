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

type Role string

const (
	LeaderRole Role = "LEADER"
	DeputyRole Role = "DEPUTY"
	MemberRole Role = "MEMBER"
)

type RequestStatus string

const (
	PendingStatus  RequestStatus = "PENDING"
	AcceptedStatus RequestStatus = "ACCEPTED"
	RejectedStatus RequestStatus = "REJECTED"
)

type Team struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	YouTubeURL  string    `json:"youtubeUrl"`
	Guideline   string    `json:"guideline"`
	AvatarURL   *string   `json:"avatarUrl,omitempty"`
	JoinCode    string    `json:"joinCode,omitempty"`
	Role        Role      `json:"role"`
	MemberCount int       `json:"memberCount"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type Member struct {
	UserID            string    `json:"userId"`
	Nickname          string    `json:"nickname"`
	AvatarURL         string    `json:"avatarUrl,omitempty"`
	Role              Role      `json:"role"`
	WarningCount      int       `json:"warningCount"`
	CanCreateProjects bool      `json:"canCreateProjects"`
	JoinedAt          time.Time `json:"joinedAt"`
}

type JoinRequest struct {
	ID        string        `json:"id"`
	TeamID    string        `json:"teamId"`
	TeamName  string        `json:"teamName,omitempty"`
	UserID    string        `json:"userId"`
	Nickname  string        `json:"nickname"`
	Status    RequestStatus `json:"status"`
	CreatedAt time.Time     `json:"createdAt"`
}

type CreateTeam struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

type UpdateTeam struct {
	Name        string  `json:"name" binding:"required"`
	Description string  `json:"description"`
	YouTubeURL  string  `json:"youtubeUrl"`
	Guideline   string  `json:"guideline"`
	AvatarURL   *string `json:"avatarUrl"`
}

type JoinTeam struct {
	JoinCode string `json:"joinCode" binding:"required"`
	Nickname string `json:"nickname" binding:"required"`
}

type ReviewRequest struct {
	Accept bool `json:"accept"`
}

type SetRole struct {
	Role Role `json:"role" binding:"required"`
}

type MemberPermission struct {
	CanCreateProjects bool `json:"canCreateProjects"`
}

type ReorderTeams struct {
	TeamIDs []string `json:"teamIds" binding:"required"`
}
