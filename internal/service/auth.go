// Package service provides the service layer for handling authentication-related operations.
package service

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/ealia28/avito-merch2025internship/internal/domain"
)

// ErrInvalidCredentials is returned when the provided username and password combination is incorrect.
var ErrInvalidCredentials = errors.New("invalid credentials")

// UserRepository defines the interface for user data access.
type UserRepository interface {
	GetByUsername(ctx context.Context, username string) (*domain.User, error)
	Create(ctx context.Context, username string, passwordHash string) (domain.User, error)
}

// TokenGenerator defines the interface for generating authentication tokens.
type TokenGenerator interface {
	Generate(userID int64) (string, error)
}

// AuthService handles authentication-related operations, including user login and registration.
type AuthService struct {
	users      UserRepository
	tokens     TokenGenerator
	bcryptCost int
}

// NewAuthService creates a new instance of AuthService with the given user repository, token generator, and bcrypt cost.
func NewAuthService(user UserRepository, tokens TokenGenerator, bcryptCost int) *AuthService {
	return &AuthService{
		users:      user,
		tokens:     tokens,
		bcryptCost: bcryptCost,
	}
}

// hashPassword generates a bcrypt hash of the given password.
func (s *AuthService) hashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost)
}

// checkPassword verifies if the given password matches the hashed password.
func (s *AuthService) checkPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// login attempts to authenticate the user with the given password and returns a token if successful.
func (s *AuthService) login(user *domain.User, password string) (string, error) {
	if err := s.checkPassword(user.PasswordHash, password); err != nil {
		return "", ErrInvalidCredentials
	}
	return s.tokens.Generate(user.ID)
}

// Auth handles the authentication process, including user login and registration.
// It returns a token if the authentication is successful, or an error if it fails.
func (s *AuthService) Auth(ctx context.Context, username, password string) (string, error) {
	user, err := s.users.GetByUsername(ctx, username)
	if err == nil {
		return s.login(user, password)
	}

	if !errors.Is(err, domain.ErrUserNotFound) {
		return "", fmt.Errorf("get user: %w", err)
	}
	hash, err := s.hashPassword(password)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	created, err := s.users.Create(ctx, username, string(hash))
	if err == nil {
		return s.tokens.Generate(created.ID)
	}
	if !errors.Is(err, domain.ErrUserExists) {
		return "", fmt.Errorf("create user: %w", err)
	}
	user, err = s.users.GetByUsername(ctx, username)
	if err != nil {
		return "", fmt.Errorf("get user: %w", err)
	}
	return s.login(user, password)
}
