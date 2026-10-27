package service

import (
	"context"
	"crypto/rand"
	"errors"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/team/model"
)

type Repository interface {
	Create(context.Context, string, string, string, model.CreateTeam) (model.Team, error)
	List(context.Context, string) ([]model.Team, error)
	Get(context.Context, string, string) (model.Team, error)
	NameAvailable(context.Context, string, string) (bool, error)
	Update(context.Context, string, string, model.UpdateTeam) (model.Team, error)
	Delete(context.Context, string, string) error
	RequestJoin(context.Context, string, string, string) (model.JoinRequest, error)
	Requests(context.Context, string, string) ([]model.JoinRequest, error)
	ReviewRequest(context.Context, string, string, string, bool) error
	Members(context.Context, string, string) ([]model.Member, error)
	SetRole(context.Context, string, string, string, model.Role) error
	SetProjectCreation(context.Context, string, string, string, bool) error
	RemoveMember(context.Context, string, string, string) error
	WarnMember(context.Context, string, string, string) (int, error)
	Reorder(context.Context, string, []string) error
}

type TeamService struct{ repository Repository }

func NewTeamService(repository Repository) *TeamService {
	return &TeamService{repository: repository}
}

func (s *TeamService) Create(ctx context.Context, userID, nickname string, input model.CreateTeam) (model.Team, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	if !validText(input.Name, 1, 80) || !validText(input.Description, 0, 4000) {
		return model.Team{}, model.ErrInvalid
	}
	for attempt := 0; attempt < 3; attempt++ {
		code, err := joinCode()
		if err != nil {
			return model.Team{}, err
		}
		team, err := s.repository.Create(ctx, userID, nickname, code, input)
		if err == nil || !errors.Is(err, model.ErrConflict) {
			return team, err
		}
	}
	return model.Team{}, model.ErrConflict
}

func (s *TeamService) List(ctx context.Context, userID string) ([]model.Team, error) {
	return s.repository.List(ctx, userID)
}

func (s *TeamService) Get(ctx context.Context, userID, teamID string) (model.Team, error) {
	return s.repository.Get(ctx, userID, teamID)
}

func (s *TeamService) NameAvailable(ctx context.Context, name, excludeTeamID string) (bool, error) {
	name = strings.TrimSpace(name)
	if !validText(name, 1, 80) {
		return false, model.ErrInvalid
	}
	return s.repository.NameAvailable(ctx, name, excludeTeamID)
}

func (s *TeamService) Update(ctx context.Context, userID, teamID string, input model.UpdateTeam) (model.Team, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	input.YouTubeURL = strings.TrimSpace(input.YouTubeURL)
	input.Guideline = strings.TrimSpace(input.Guideline)
	if !validText(input.Name, 1, 80) || !validText(input.Description, 0, 4000) || !validText(input.Guideline, 0, 8000) || !validURL(input.YouTubeURL) || !validOptionalURL(input.AvatarURL) {
		return model.Team{}, model.ErrInvalid
	}
	return s.repository.Update(ctx, userID, teamID, input)
}

func (s *TeamService) Delete(ctx context.Context, userID, teamID string) error {
	return s.repository.Delete(ctx, userID, teamID)
}

func (s *TeamService) RequestJoin(ctx context.Context, userID, joinCode, nickname string) (model.JoinRequest, error) {
	joinCode = strings.ToUpper(strings.TrimSpace(joinCode))
	nickname = strings.TrimSpace(nickname)
	if len(joinCode) < 6 || len(joinCode) > 16 || !validText(nickname, 1, 50) {
		return model.JoinRequest{}, model.ErrInvalid
	}
	return s.repository.RequestJoin(ctx, userID, joinCode, nickname)
}

func (s *TeamService) Requests(ctx context.Context, userID, teamID string) ([]model.JoinRequest, error) {
	return s.repository.Requests(ctx, userID, teamID)
}

func (s *TeamService) ReviewRequest(ctx context.Context, userID, teamID, requestID string, accept bool) error {
	return s.repository.ReviewRequest(ctx, userID, teamID, requestID, accept)
}

func (s *TeamService) Members(ctx context.Context, userID, teamID string) ([]model.Member, error) {
	return s.repository.Members(ctx, userID, teamID)
}

func (s *TeamService) SetRole(ctx context.Context, userID, teamID, targetID string, role model.Role) error {
	return s.repository.SetRole(ctx, userID, teamID, targetID, role)
}

func (s *TeamService) SetProjectCreation(ctx context.Context, userID, teamID, targetID string, allowed bool) error {
	return s.repository.SetProjectCreation(ctx, userID, teamID, targetID, allowed)
}

func (s *TeamService) RemoveMember(ctx context.Context, userID, teamID, targetID string) error {
	return s.repository.RemoveMember(ctx, userID, teamID, targetID)
}

func (s *TeamService) WarnMember(ctx context.Context, userID, teamID, targetID string) (int, error) {
	return s.repository.WarnMember(ctx, userID, teamID, targetID)
}

func (s *TeamService) Reorder(ctx context.Context, userID string, teamIDs []string) error {
	if len(teamIDs) == 0 || len(teamIDs) > 100 {
		return model.ErrInvalid
	}
	seen := make(map[string]struct{}, len(teamIDs))
	for _, id := range teamIDs {
		if _, exists := seen[id]; exists || strings.TrimSpace(id) == "" {
			return model.ErrInvalid
		}
		seen[id] = struct{}{}
	}
	return s.repository.Reorder(ctx, userID, teamIDs)
}

func joinCode() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	bytes := make([]byte, 10)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	for index := range bytes {
		bytes[index] = alphabet[int(bytes[index])%len(alphabet)]
	}
	return string(bytes), nil
}

func validText(value string, min, max int) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	if length < min || length > max {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) || unicode.Is(unicode.Cf, char) {
			return false
		}
	}
	return true
}

func validURL(value string) bool {
	if value == "" {
		return true
	}
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.Host != "" && parsed.User == nil && parsed.Scheme == "https" && len(value) <= 2048
}

func validOptionalURL(value *string) bool {
	if value == nil || strings.TrimSpace(*value) == "" {
		return true
	}
	if strings.HasPrefix(*value, "/media/") {
		return !strings.Contains(*value, "..") && !strings.ContainsAny(*value, "?#\\") && len(*value) <= 512
	}
	return validURL(*value)
}
