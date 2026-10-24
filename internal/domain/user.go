// Package domain defines the core entities and errors for the application.
package domain

import "errors"

// User represents a user entity in the domain.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Balance      int
}

// Errors related to user operations.
var (
	ErrUserNotFound = errors.New("user not found")
	ErrUserExists   = errors.New("user already exists")
)
