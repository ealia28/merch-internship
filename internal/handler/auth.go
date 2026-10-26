package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/ealia28/avito-merch2025internship/internal/service"
)

type Authenticator interface {
	Auth(ctx context.Context, username, password string) (string, error)
}

type AuthHandler struct {
	auth   Authenticator
	logger *slog.Logger
}

func NewAuthHandler(auth Authenticator, logger *slog.Logger) *AuthHandler {
	return &AuthHandler{
		auth:   auth,
		logger: logger,
	}
}

type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResponse struct {
	Token string `json:"token"`
}

func (h *AuthHandler) Auth(w http.ResponseWriter, r *http.Request) {
	var req authRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	token, err := h.auth.Auth(r.Context(), req.Username, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		h.logger.Error("auth failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, authResponse{Token: token})
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, message string) error {
	return writeJSON(w, status, map[string]string{"errors": message})
}
