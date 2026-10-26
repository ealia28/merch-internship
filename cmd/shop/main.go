// Command shop запускает HTTP-сервис магазина мерча Авито.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ealia28/avito-merch2025internship/internal/config"
	"github.com/ealia28/avito-merch2025internship/internal/handler"
	"github.com/ealia28/avito-merch2025internship/internal/service"
	"github.com/ealia28/avito-merch2025internship/internal/storage"
	"github.com/ealia28/avito-merch2025internship/internal/token"
)

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	pool, err := storage.NewPool(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("create storage pool: %w", err)
	}
	defer pool.Close()

	userRepo := storage.NewUserRepo(pool)

	tokens := token.NewManager(cfg.JWT.Secret, cfg.JWT.TTL)

	authSvc := service.NewAuthService(userRepo, tokens, cfg.Auth.BcryptCost)

	authHandler := handler.NewAuthHandler(authSvc, logger)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("POST /api/auth", authHandler.Auth)

	srv := &http.Server{
		Addr:              ":" + cfg.Server.Port,
		Handler:           mux,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
	}
	logger.Info("starting server", "addr", srv.Addr)

	errch := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errch <- err
		}
	}()

	select {
	case err := <-errch:
		return fmt.Errorf("listen and serve: %w", err)
	case <-ctx.Done():
		stop()
		logger.Info("shutting down server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer cancel()
		err := srv.Shutdown(shutdownCtx)
		if err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		logger.Info("server stopped gracefully")
	}
	return nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("failed to run application", "error", err)
		os.Exit(1)
	}
}
