// Package token provides JWT token generation and parsing.
package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// claims represents the JWT claims structure.
type claims struct {
	UserID int64 `json:"user_id"`
	jwt.RegisteredClaims
}

// Manager handles JWT token generation and parsing.
type Manager struct {
	secret []byte
	ttl    time.Duration
}

// NewManager creates a new token manager with the given secret and TTL.
func NewManager(secret string, ttl time.Duration) *Manager {
	return &Manager{
		secret: []byte(secret),
		ttl:    ttl,
	}
}

// Generate creates a new JWT token for the given user ID.
func (m *Manager) Generate(userID int64) (string, error) {
	claims := claims{
		UserID:    userID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.ttl)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	if userID <= 0 {
		return "", fmt.Errorf("invalid user ID %w", ErrInvalidToken)
	}
	return token.SignedString(m.secret)
}

// Parse parses the given JWT token string and returns the user ID if valid.
func (m *Manager) Parse(tokenStr string) (int64, error) {
	claims := &claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(_ *jwt.Token) (interface{}, error) {
		return m.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired())
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	return claims.UserID, nil
}

// ErrInvalidToken is returned when the token is invalid.
var ErrInvalidToken = errors.New("invalid token")
