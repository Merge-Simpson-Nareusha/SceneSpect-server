package service

import (
	"context"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/project/model"
)

type Repository interface {
	Create(context.Context, string, string, model.CreateProject) (model.Project, error)
	List(context.Context, string, string, string) ([]model.Project, error)
	Get(context.Context, string, string) (model.Project, error)
	Update(context.Context, string, string, model.UpdateProject) (model.Project, error)
	Delete(context.Context, string, string) error
	Members(context.Context, string, string) ([]model.ProjectMember, error)
	Grant(context.Context, string, string, string, model.AccessLevel) error
	Revoke(context.Context, string, string, string) error
	RequestAccess(context.Context, string, string, model.AccessLevel, string) (model.AccessRequest, error)
	AccessRequests(context.Context, string, string) ([]model.AccessRequest, error)
	ReviewAccess(context.Context, string, string, string, bool) error
	RequestDeletion(context.Context, string, string, string) (model.DeleteRequest, error)
	DeleteRequests(context.Context, string, string) ([]model.DeleteRequest, error)
	ReviewDeletion(context.Context, string, string, string, bool) error
}

type ProjectService struct{ repository Repository }

func NewProjectService(repository Repository) *ProjectService {
	return &ProjectService{repository: repository}
}

func (s *ProjectService) Create(ctx context.Context, userID, teamID string, input model.CreateProject) (model.Project, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	if input.Visibility == "" {
		input.Visibility = model.TeamVisibility
	}
	if !validText(input.Name, 1, 100) || !validText(input.Description, 0, 8000) || !validOptionalURL(input.ThumbnailURL) || !validVisibility(input.Visibility) {
		return model.Project{}, model.ErrInvalid
	}
	return s.repository.Create(ctx, userID, teamID, input)
}

func (s *ProjectService) List(ctx context.Context, userID, teamID, sort string) ([]model.Project, error) {
	if sort == "" {
		sort = "recent"
	}
	if sort != "recent" && sort != "name" {
		return nil, model.ErrInvalid
	}
	return s.repository.List(ctx, userID, teamID, sort)
}

func (s *ProjectService) Get(ctx context.Context, userID, projectID string) (model.Project, error) {
	return s.repository.Get(ctx, userID, projectID)
}

func (s *ProjectService) Update(ctx context.Context, userID, projectID string, input model.UpdateProject) (model.Project, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	if input.Visibility == "" {
		current, err := s.repository.Get(ctx, userID, projectID)
		if err != nil {
			return model.Project{}, err
		}
		input.Visibility = current.Visibility
	}
	if !validText(input.Name, 1, 100) || !validText(input.Description, 0, 8000) || !validOptionalURL(input.ThumbnailURL) || !validVisibility(input.Visibility) {
		return model.Project{}, model.ErrInvalid
	}
	return s.repository.Update(ctx, userID, projectID, input)
}

func (s *ProjectService) Delete(ctx context.Context, userID, projectID string) error {
	return s.repository.Delete(ctx, userID, projectID)
}

func (s *ProjectService) Members(ctx context.Context, userID, projectID string) ([]model.ProjectMember, error) {
	return s.repository.Members(ctx, userID, projectID)
}

func (s *ProjectService) Grant(ctx context.Context, actorID, projectID, targetID string, level model.AccessLevel) error {
	return s.repository.Grant(ctx, actorID, projectID, targetID, level)
}

func (s *ProjectService) Revoke(ctx context.Context, actorID, projectID, targetID string) error {
	return s.repository.Revoke(ctx, actorID, projectID, targetID)
}

func (s *ProjectService) RequestAccess(ctx context.Context, userID, projectID string, input model.RequestAccess) (model.AccessRequest, error) {
	if input.AccessLevel == "" {
		input.AccessLevel = model.ViewerAccess
	}
	input.Message = strings.TrimSpace(input.Message)
	if !validText(input.Message, 0, 2000) {
		return model.AccessRequest{}, model.ErrInvalid
	}
	return s.repository.RequestAccess(ctx, userID, projectID, input.AccessLevel, input.Message)
}

func (s *ProjectService) AccessRequests(ctx context.Context, userID, teamID string) ([]model.AccessRequest, error) {
	return s.repository.AccessRequests(ctx, userID, teamID)
}

func (s *ProjectService) ReviewAccess(ctx context.Context, userID, teamID, requestID string, accept bool) error {
	return s.repository.ReviewAccess(ctx, userID, teamID, requestID, accept)
}

func (s *ProjectService) RequestDeletion(ctx context.Context, userID, projectID, message string) (model.DeleteRequest, error) {
	message = strings.TrimSpace(message)
	if !validText(message, 0, 2000) {
		return model.DeleteRequest{}, model.ErrInvalid
	}
	return s.repository.RequestDeletion(ctx, userID, projectID, message)
}

func (s *ProjectService) DeleteRequests(ctx context.Context, userID, teamID string) ([]model.DeleteRequest, error) {
	return s.repository.DeleteRequests(ctx, userID, teamID)
}

func (s *ProjectService) ReviewDeletion(ctx context.Context, userID, teamID, requestID string, accept bool) error {
	return s.repository.ReviewDeletion(ctx, userID, teamID, requestID, accept)
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

func validOptionalURL(value *string) bool {
	if value == nil || strings.TrimSpace(*value) == "" {
		return true
	}
	if strings.HasPrefix(*value, "/media/") {
		return !strings.Contains(*value, "..") && !strings.ContainsAny(*value, "?#\\") && len(*value) <= 512
	}
	parsed, err := url.ParseRequestURI(*value)
	return err == nil && parsed.Host != "" && parsed.User == nil && parsed.Scheme == "https" && len(*value) <= 2048
}

func validVisibility(visibility model.Visibility) bool {
	return visibility == model.TeamVisibility || visibility == model.SelectedVisibility
}
