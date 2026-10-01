package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/config"
	authmiddleware "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/middleware"
)

type accountUseCaseStub struct {
	UseCase
	user             model.User
	authenticateErr  error
	updateErr        error
	receivedUserID   string
	receivedNickname string
}

func (s *accountUseCaseStub) Authenticate(context.Context, string) (model.User, error) {
	return s.user, s.authenticateErr
}

func (s *accountUseCaseStub) UpdateNickname(_ context.Context, userID, nickname string) (model.User, error) {
	s.receivedUserID = userID
	s.receivedNickname = nickname
	if s.updateErr != nil {
		return model.User{}, s.updateErr
	}
	s.user.Nickname = nickname
	return s.user, nil
}

func newAccountTestRouter(useCase *accountUseCaseStub) *gin.Engine {
	gin.SetMode(gin.TestMode)
	handler := NewHandler(useCase, config.Config{WebOrigin: "https://app.example"})
	router := gin.New()
	router.Use(handler.CORS())
	requireAuth := authmiddleware.Authenticate(handler.Authenticator())
	router.GET("/me", requireAuth, handler.Me)
	router.PATCH("/me/nickname", requireAuth, handler.NicknameUpdate)
	return router
}

func TestMeRequiresAuthentication(t *testing.T) {
	router := newAccountTestRouter(&accountUseCaseStub{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/me", nil)

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestMeReturnsAuthenticatedProfileWithoutPasswordFields(t *testing.T) {
	useCase := &accountUseCaseStub{user: model.User{
		ID: "user-id", Email: "user@example.com", Username: "login-name", Nickname: "display-name",
		Role: "USER", Status: "ACTIVE", PasswordHash: "must-not-leak", PasswordVersion: 7,
	}}
	router := newAccountTestRouter(useCase)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/me", nil)
	request.Header.Set("Authorization", "Bearer access-token")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var body struct {
		User map[string]any `json:"user"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.User["id"] != "user-id" || body.User["nickname"] != "display-name" {
		t.Fatalf("unexpected profile response: %#v", body.User)
	}
	if _, exists := body.User["password_hash"]; exists {
		t.Fatal("profile response contains a password hash field")
	}
	if _, exists := body.User["passwordVersion"]; exists {
		t.Fatal("profile response contains a password version field")
	}
	if strings.Contains(recorder.Body.String(), "must-not-leak") {
		t.Fatal("profile response contains the password hash")
	}
}

func TestNicknameUpdateUsesAuthenticatedUserAndReturnsUpdatedProfile(t *testing.T) {
	useCase := &accountUseCaseStub{user: model.User{
		ID: "user-id", Email: "user@example.com", Username: "login-name", Nickname: "old-name", Role: "USER", Status: "ACTIVE",
	}}
	router := newAccountTestRouter(useCase)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/me/nickname", strings.NewReader(`{"nickname":"new-name"}`))
	request.Header.Set("Authorization", "Bearer access-token")
	request.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if useCase.receivedUserID != "user-id" || useCase.receivedNickname != "new-name" {
		t.Fatalf("update arguments = (%q, %q)", useCase.receivedUserID, useCase.receivedNickname)
	}
	var body struct {
		User struct {
			Username string `json:"username"`
			Nickname string `json:"nickname"`
		} `json:"user"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.User.Username != "login-name" || body.User.Nickname != "new-name" {
		t.Fatalf("unexpected updated profile: %+v", body.User)
	}
}

func TestNicknameUpdateReturnsConflictForDuplicateNickname(t *testing.T) {
	useCase := &accountUseCaseStub{user: model.User{ID: "user-id"}, updateErr: model.ErrConflict}
	router := newAccountTestRouter(useCase)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/me/nickname", strings.NewReader(`{"nickname":"taken-name"}`))
	request.Header.Set("Authorization", "Bearer access-token")
	request.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}
}

func TestCORSAllowsNicknamePatch(t *testing.T) {
	router := newAccountTestRouter(&accountUseCaseStub{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodOptions, "/me/nickname", nil)
	request.Header.Set("Origin", "https://app.example")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if methods := recorder.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(methods, "PATCH") {
		t.Fatalf("CORS methods = %q, want PATCH", methods)
	}
}
