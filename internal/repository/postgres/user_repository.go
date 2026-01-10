package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"g-auth/internal/domain"
)

type userRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *userRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
        INSERT INTO users (email, password, name, created_at, updated_at)
        VALUES ($1, $2, $3, NOW(), NOW())
        RETURNING id, created_at, updated_at
    `

	var idStr string
	err := r.db.QueryRowContext(
		ctx,
		query,
		user.Email,
		user.Password,
		user.Name,
	).Scan(&idStr, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return err
	}

	user.ID, err = uuid.Parse(idStr)
	if err != nil {
		return err
	}

	return nil
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
        SELECT id, email, password, name, created_at, updated_at
        FROM users
        WHERE email = $1
    `

	user := &domain.User{}
	var idStr string
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&idStr,
		&user.Email,
		&user.Password,
		&user.Name,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	user.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *userRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
        SELECT id, email, password, name, created_at, updated_at
        FROM users
        WHERE id = $1
    `

	user := &domain.User{}
	var idStr string
	err := r.db.QueryRowContext(ctx, query, id.String()).Scan(
		&idStr,
		&user.Email,
		&user.Password,
		&user.Name,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	user.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, err
	}

	return user, nil
}
