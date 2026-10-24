package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ealia28/avito-merch2025internship/internal/domain"
)

// UserRepo represents the repository for user-related database operations.
type UserRepo struct {
	pool *pgxpool.Pool
}

// NewUserRepo creates a new instance of UserRepo with the given database connection pool.
func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

// GetByUsername retrieves a user from the database by their username.
// It returns a pointer to the user if found, or an error if the user is not found or if there is a database error.
func (r *UserRepo) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	var user domain.User
	err := r.pool.QueryRow(ctx, "SELECT id, username, password_hash, balance FROM users WHERE username = $1", username).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Balance)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}
	return &user, nil
}

// Create inserts a new user into the database with the given username and password hash.
// It returns the created user if successful, or an error if the user already exists or if there is a database error.
func (r *UserRepo) Create(ctx context.Context, username string, passwordHash string) (domain.User, error) {
	var user domain.User
	err := r.pool.QueryRow(ctx, "INSERT INTO users (username, password_hash) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING RETURNING id, username, password_hash, balance", username, passwordHash).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Balance)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, domain.ErrUserExists
	}
	if err != nil {
		return domain.User{}, fmt.Errorf("failed to create user: %w", err)
	}
	return user, nil
}
