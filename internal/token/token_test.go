package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const secret = "test-secret-at-least-32-bytes-long!!"

func TestGenerateParse(t *testing.T) {
	m := NewManager(secret, time.Hour)
	tests := []struct {
		name   string
		userID int64
	}{
		{
			name:   "regular ID",
			userID: 1,
		},
		{
			name:   "large ID",
			userID: 1234567890123456789,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := m.Generate(tt.userID)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}
			parsedUserID, err := m.Parse(token)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if parsedUserID != tt.userID {
				t.Errorf("Parse() = %v, want %v", parsedUserID, tt.userID)
			}
		})
	}
}

func TestGenerateInvalidUserID(t *testing.T) {
	m := NewManager(secret, time.Hour)
	_, err := m.Generate(0)
	if err == nil {
		t.Errorf("Generate() error = %v, wantErr true", err)
	}
}

func TestParseInvalidToken(t *testing.T) {
	m := NewManager(secret, time.Hour)

	expiredToken, err := NewManager(secret, -time.Hour).Generate(1)
	if err != nil {
		t.Fatalf("setup expired: %v", err)
	}

	wrongSecretToken, err := NewManager("wrong-secret-at-least-32-bytes-long!!", time.Hour).Generate(1)
	if err != nil {
		t.Fatalf("setup wrong secret: %v", err)
	}

	// alg none: valid exp, so the token is rejected because of the algorithm, not a missing exp.
	noneClaims := claims{
		UserID:    1,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	algNoneToken, err := jwt.NewWithClaims(jwt.SigningMethodNone, noneClaims).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("setup alg none: %v", err)
	}

	// tampered: user 1 swaps the payload for {"user_id":2,...} and keeps the old signature.
	// The payload is valid JSON, so Parse must fail exactly on the signature check.
	validToken, err := m.Generate(1)
	if err != nil {
		t.Fatalf("setup tampered: %v", err)
	}
	forgedPayload, err := json.Marshal(claims{
		UserID:    2,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("setup tampered: %v", err)
	}
	parts := strings.Split(validToken, ".") // header, payload, signature
	parts[1] = base64.RawURLEncoding.EncodeToString(forgedPayload)
	tamperedToken := strings.Join(parts, ".")

	tests := []struct {
		name  string
		token string
	}{
		{name: "expired token", token: expiredToken},
		{name: "wrong secret", token: wrongSecretToken},
		{name: "alg none", token: algNoneToken},
		{name: "tampered token", token: tamperedToken},
		{name: "garbage token", token: "this.is.not.a.valid.token"},
		{name: "empty token", token: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userID, err := m.Parse(tt.token)
			if !errors.Is(err, ErrInvalidToken) {
				t.Errorf("Parse() error = %v, want ErrInvalidToken", err)
			}
			if userID != 0 {
				t.Errorf("Parse() userID = %d, want 0", userID)
			}
		})
	}
}
