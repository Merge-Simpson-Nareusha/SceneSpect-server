package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

type nicknameRepositoryStub struct {
	AuthRepository
	user     model.User
	err      error
	calls    int
	userID   string
	nickname string
}

func (r *nicknameRepositoryStub) UpdateNickname(_ context.Context, userID, nickname string) (model.User, error) {
	r.calls++
	r.userID = userID
	r.nickname = nickname
	return r.user, r.err
}

func TestUpdateNicknameRejectsInvalidValueBeforeRepositoryWrite(t *testing.T) {
	repository := &nicknameRepositoryStub{}
	authService := NewAuthService(repository, nil, nil, security.TokenManager{}, nil, 0, 0)

	for _, nickname := range []string{"", " padded ", "name@example.com", strings.Repeat("a", 51)} {
		if _, err := authService.UpdateNickname(context.Background(), "user-id", nickname); !errors.Is(err, model.ErrInvalid) {
			t.Errorf("UpdateNickname(%q) error = %v, want %v", nickname, err, model.ErrInvalid)
		}
	}
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d, want 0", repository.calls)
	}
}

func TestUpdateNicknamePassesValidValueToRepository(t *testing.T) {
	repository := &nicknameRepositoryStub{user: model.User{ID: "user-id", Nickname: "new-name"}}
	authService := NewAuthService(repository, nil, nil, security.TokenManager{}, nil, 0, 0)

	got, err := authService.UpdateNickname(context.Background(), "user-id", "new-name")
	if err != nil {
		t.Fatalf("UpdateNickname returned error: %v", err)
	}
	if got.Nickname != "new-name" || repository.calls != 1 || repository.userID != "user-id" || repository.nickname != "new-name" {
		t.Fatalf("unexpected repository result: user=%+v calls=%d id=%q nickname=%q", got, repository.calls, repository.userID, repository.nickname)
	}
}
