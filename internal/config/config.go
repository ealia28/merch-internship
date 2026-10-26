// Package config загружает конфигурацию сервиса из переменных окружения.
package config

import (
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/caarlos0/env/v11"
	"golang.org/x/crypto/bcrypt"
)

const minJWTSecretLen = 32

// Server — настройки HTTP-сервера: порт и таймауты.
type Server struct {
	Port              string        `env:"PORT" envDefault:"8080"`
	ReadHeaderTimeout time.Duration `env:"READ_HEADER_TIMEOUT" envDefault:"5s"`
	ReadTimeout       time.Duration `env:"READ_TIMEOUT" envDefault:"10s"`
	WriteTimeout      time.Duration `env:"WRITE_TIMEOUT" envDefault:"10s"`
	IdleTimeout       time.Duration `env:"IDLE_TIMEOUT" envDefault:"60s"`
	ShutdownTimeout   time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"10s"`
}

// Database — параметры подключения к PostgreSQL.
type Database struct {
	Host            string        `env:"HOST" envDefault:"localhost"`
	Port            string        `env:"PORT" envDefault:"5432"`
	User            string        `env:"USER,required"`
	Password        string        `env:"PASSWORD,required"`
	Name            string        `env:"NAME,required"`
	SSLMode         string        `env:"SSLMODE" envDefault:"disable"`
	MaxConns        int32         `env:"MAX_CONNS" envDefault:"25"`
	MinConns        int32         `env:"MIN_CONNS" envDefault:"5"`
	MaxConnLifetime time.Duration `env:"MAX_CONN_LIFETIME" envDefault:"1h"`
	MaxConnIdleTime time.Duration `env:"MAX_CONN_IDLE_TIME" envDefault:"30m"`
}

// DSN возвращает строку подключения к PostgreSQL в формате URL.
func (d Database) DSN() string {
	u := &url.URL{Scheme: "postgres", User: url.UserPassword(d.User, d.Password), Host: net.JoinHostPort(d.Host, d.Port), Path: d.Name}
	RawQuery := url.Values{}
	RawQuery.Set("sslmode", d.SSLMode)
	u.RawQuery = RawQuery.Encode()
	return u.String()
}

// JWT — настройки выпуска и проверки токенов.
type JWT struct {
	Secret string        `env:"SECRET,required"`
	TTL    time.Duration `env:"TTL" envDefault:"24h"`
}

// Config — полная конфигурация сервиса.
type Config struct {
	Server   Server   `envPrefix:"SERVER_"`
	Database Database `envPrefix:"DATABASE_"`
	JWT      JWT      `envPrefix:"JWT_"`
	Auth     Auth     `envPrefix:"AUTH_"`
}

type Auth struct {
	BcryptCost int `env:"BCRYPT_COST" envDefault:"10"`
}

// Load читает конфигурацию из переменных окружения и проверяет её.
// Возвращает ошибку, если не заданы обязательные переменные
// или JWT-секрет короче minJWTSecretLen байт.
func Load() (*Config, error) {
	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("parse env: %w", err)
	}
	if len(cfg.JWT.Secret) < minJWTSecretLen {
		return nil, fmt.Errorf("jwt secret must be at least %d bytes long", minJWTSecretLen)
	}
	if cfg.Database.MaxConns <= 0 {
		return nil, fmt.Errorf("database max conns must be positive")
	}
	if cfg.Database.MinConns < 0 {
		return nil, fmt.Errorf("database min conns(%d) must be positive", cfg.Database.MinConns)
	}
	if cfg.Database.MaxConns < cfg.Database.MinConns {
		return nil, fmt.Errorf("database max conns(%d) must be greater than or equal to min conns(%d)", cfg.Database.MaxConns, cfg.Database.MinConns)
	}
	if bcrypt.MinCost > cfg.Auth.BcryptCost || cfg.Auth.BcryptCost > bcrypt.MaxCost {
		return nil, fmt.Errorf("auth bcrypt cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}
	return &cfg, nil
}
