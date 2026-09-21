package security

import (
	"testing"
	"time"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
)

func TestNicknameCandidateAddsSuffixAndPreservesLimit(t *testing.T) {
	base := "a very long nickname that should be truncated safely"
	got := NicknameCandidate(base, 3)
	if len([]rune(got)) > 50 || got[len(got)-2:] != "-3" {
		t.Fatalf("unexpected candidate: %q", got)
	}
	if NicknameCandidate("kimjaeyun", 1) != "kimjaeyun" || NicknameCandidate("kimjaeyun", 2) != "kimjaeyun-2" {
		t.Fatal("suffix policy changed")
	}
}

func TestNormalizeEmailAndMask(t *testing.T) {
	if got, err := NormalizeEmail(" User@Example.COM "); err != nil || got != "user@example.com" {
		t.Fatalf("normalize: %q %v", got, err)
	}
	if _, err := NormalizeEmail(`a"b@example.com`); err == nil {
		t.Fatal("quoted local part must be rejected")
	}
	if got := domain.MaskEmail("kimjaeyun@example.com"); got != "ki*******@example.com" {
		t.Fatalf("mask: %q", got)
	}
}

func TestTokenManagerRejectsWrongIssuerAndAcceptsValidToken(t *testing.T) {
	m := TokenManager{Key: []byte("01234567890123456789012345678901"), Issuer: "issuer", Audience: "audience", TTL: time.Minute}
	raw, err := m.Issue("00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", "USER")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := m.Parse(raw)
	if err != nil || claims.Role != "USER" {
		t.Fatalf("parse: %+v %v", claims, err)
	}
	wrong := m
	wrong.Issuer = "other"
	if _, err = wrong.Parse(raw); err == nil {
		t.Fatal("wrong issuer accepted")
	}
}
