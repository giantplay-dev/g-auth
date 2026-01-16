package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

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
        INSERT INTO users (email, password, name, email_verified, created_at, updated_at)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        RETURNING id, created_at, updated_at
    `

	var idStr string
	err := r.db.QueryRowContext(
		ctx,
		query,
		user.Email,
		user.Password,
		user.Name,
		user.EmailVerified,
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
        SELECT id, email, password, name, email_verified, verification_token, verification_token_expires_at, reset_token, reset_token_expires_at, refresh_token, refresh_token_expires_at, created_at, updated_at
        FROM users
        WHERE email = $1
    `

	user := &domain.User{}
	var idStr string
	var verificationToken, verificationTokenExpiresAt, resetToken, resetTokenExpiresAt, refreshToken, refreshTokenExpiresAt sql.NullString
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&idStr,
		&user.Email,
		&user.Password,
		&user.Name,
		&user.EmailVerified,
		&verificationToken,
		&verificationTokenExpiresAt,
		&resetToken,
		&resetTokenExpiresAt,
		&refreshToken,
		&refreshTokenExpiresAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

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

	if verificationToken.Valid {
		user.VerificationToken = &verificationToken.String
	}
	if verificationTokenExpiresAt.Valid {
		if expiresAt, parseErr := time.Parse(time.RFC3339, verificationTokenExpiresAt.String); parseErr == nil {
			user.VerificationTokenExpiresAt = &expiresAt
		}
	}
	if resetToken.Valid {
		user.ResetToken = &resetToken.String
	}
	if resetTokenExpiresAt.Valid {
		if expiresAt, parseErr := time.Parse(time.RFC3339, resetTokenExpiresAt.String); parseErr == nil {
			user.ResetTokenExpiresAt = &expiresAt
		}
	}
	if refreshToken.Valid {
		user.RefreshToken = &refreshToken.String
	}
	if refreshTokenExpiresAt.Valid {
		if expiresAt, parseErr := time.Parse(time.RFC3339, refreshTokenExpiresAt.String); parseErr == nil {
			user.RefreshTokenExpiresAt = &expiresAt
		}
	}

	return user, nil
}

func (r *userRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
        SELECT id, email, password, name, email_verified, verification_token, verification_token_expires_at, reset_token, reset_token_expires_at, refresh_token, refresh_token_expires_at, created_at, updated_at
        FROM users
        WHERE id = $1
    `

	user := &domain.User{}
	var idStr string
	var verificationToken, verificationTokenExpiresAt, resetToken, resetTokenExpiresAt, refreshToken, refreshTokenExpiresAt sql.NullString
	err := r.db.QueryRowContext(ctx, query, id.String()).Scan(
		&idStr,
		&user.Email,
		&user.Password,
		&user.Name,
		&user.EmailVerified,
		&verificationToken,
		&verificationTokenExpiresAt,
		&resetToken,
		&resetTokenExpiresAt,
		&refreshToken,
		&refreshTokenExpiresAt,
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

	if verificationToken.Valid {
		user.VerificationToken = &verificationToken.String
	}
	if verificationTokenExpiresAt.Valid {
		if expiresAt, parseErr := time.Parse(time.RFC3339, verificationTokenExpiresAt.String); parseErr == nil {
			user.VerificationTokenExpiresAt = &expiresAt
		}
	}
	if resetToken.Valid {
		user.ResetToken = &resetToken.String
	}
	if resetTokenExpiresAt.Valid {
		if expiresAt, parseErr := time.Parse(time.RFC3339, resetTokenExpiresAt.String); parseErr == nil {
			user.ResetTokenExpiresAt = &expiresAt
		}
	}
	if refreshToken.Valid {
		user.RefreshToken = &refreshToken.String
	}
	if refreshTokenExpiresAt.Valid {
		if expiresAt, parseErr := time.Parse(time.RFC3339, refreshTokenExpiresAt.String); parseErr == nil {
			user.RefreshTokenExpiresAt = &expiresAt
		}
	}

	return user, nil
}

func (r *userRepository) UpdateResetToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error {
	query := `
        UPDATE users
        SET reset_token = $1, reset_token_expires_at = $2, updated_at = NOW()
        WHERE id = $3
    `

	_, err := r.db.ExecContext(ctx, query, token, expiresAt, userID.String())
	return err
}

func (r *userRepository) GetByResetToken(ctx context.Context, token string) (*domain.User, error) {
	query := `
        SELECT id, email, password, name, reset_token, reset_token_expires_at, created_at, updated_at
        FROM users
        WHERE reset_token = $1
    `

	user := &domain.User{}
	var idStr string
	var resetToken, resetTokenExpiresAt sql.NullString
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&idStr,
		&user.Email,
		&user.Password,
		&user.Name,
		&resetToken,
		&resetTokenExpiresAt,
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

	if resetToken.Valid {
		user.ResetToken = &resetToken.String
	}
	if resetTokenExpiresAt.Valid {
		if expiresAt, parseErr := time.Parse(time.RFC3339, resetTokenExpiresAt.String); parseErr == nil {
			user.ResetTokenExpiresAt = &expiresAt
		}
	}

	return user, nil
}

func (r *userRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error {
	query := `
        UPDATE users
        SET password = $1, updated_at = NOW()
        WHERE id = $2
    `

	_, err := r.db.ExecContext(ctx, query, hashedPassword, userID.String())
	return err
}

func (r *userRepository) ClearResetToken(ctx context.Context, userID uuid.UUID) error {
	query := `
        UPDATE users
        SET reset_token = NULL, reset_token_expires_at = NULL, updated_at = NOW()
        WHERE id = $1
    `

	_, err := r.db.ExecContext(ctx, query, userID.String())
	return err
}

func (r *userRepository) UpdateRefreshToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error {
	query := `
        UPDATE users
        SET refresh_token = $1, refresh_token_expires_at = $2, updated_at = NOW()
        WHERE id = $3
    `

	_, err := r.db.ExecContext(ctx, query, token, expiresAt, userID.String())
	return err
}

func (r *userRepository) GetByRefreshToken(ctx context.Context, token string) (*domain.User, error) {
	query := `
        SELECT id, email, password, name, reset_token, reset_token_expires_at, refresh_token, refresh_token_expires_at, created_at, updated_at
        FROM users
        WHERE refresh_token = $1
    `

	user := &domain.User{}
	var resetToken, resetTokenExpiresAt, refreshToken, refreshTokenExpiresAt sql.NullString

	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.Name,
		&resetToken,
		&resetTokenExpiresAt,
		&refreshToken,
		&refreshTokenExpiresAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	if resetToken.Valid {
		user.ResetToken = &resetToken.String
	}
	if resetTokenExpiresAt.Valid {
		if expiresAt, parseErr := time.Parse(time.RFC3339, resetTokenExpiresAt.String); parseErr == nil {
			user.ResetTokenExpiresAt = &expiresAt
		}
	}
	if refreshToken.Valid {
		user.RefreshToken = &refreshToken.String
	}
	if refreshTokenExpiresAt.Valid {
		if expiresAt, parseErr := time.Parse(time.RFC3339, refreshTokenExpiresAt.String); parseErr == nil {
			user.RefreshTokenExpiresAt = &expiresAt
		}
	}

	return user, nil
}

func (r *userRepository) ClearRefreshToken(ctx context.Context, userID uuid.UUID) error {
	query := `
        UPDATE users
        SET refresh_token = NULL, refresh_token_expires_at = NULL, updated_at = NOW()
        WHERE id = $1
    `

	_, err := r.db.ExecContext(ctx, query, userID.String())
	return err
}

func (r *userRepository) UpdateVerificationToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error {
	query := `
        UPDATE users
        SET verification_token = $1, verification_token_expires_at = $2, updated_at = NOW()
        WHERE id = $3
    `

	_, err := r.db.ExecContext(ctx, query, token, expiresAt, userID.String())
	return err
}

func (r *userRepository) GetByVerificationToken(ctx context.Context, token string) (*domain.User, error) {
	query := `
        SELECT id, email, password, name, email_verified, verification_token, verification_token_expires_at, reset_token, reset_token_expires_at, refresh_token, refresh_token_expires_at, created_at, updated_at
        FROM users
        WHERE verification_token = $1
    `

	user := &domain.User{}
	var idStr string
	var verificationToken, verificationTokenExpiresAt, resetToken, resetTokenExpiresAt, refreshToken, refreshTokenExpiresAt sql.NullString
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&idStr,
		&user.Email,
		&user.Password,
		&user.Name,
		&user.EmailVerified,
		&verificationToken,
		&verificationTokenExpiresAt,
		&resetToken,
		&resetTokenExpiresAt,
		&refreshToken,
		&refreshTokenExpiresAt,
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

	if verificationToken.Valid {
		user.VerificationToken = &verificationToken.String
	}
	if verificationTokenExpiresAt.Valid {
		if expiresAt, parseErr := time.Parse(time.RFC3339, verificationTokenExpiresAt.String); parseErr == nil {
			user.VerificationTokenExpiresAt = &expiresAt
		}
	}
	if resetToken.Valid {
		user.ResetToken = &resetToken.String
	}
	if resetTokenExpiresAt.Valid {
		if expiresAt, parseErr := time.Parse(time.RFC3339, resetTokenExpiresAt.String); parseErr == nil {
			user.ResetTokenExpiresAt = &expiresAt
		}
	}
	if refreshToken.Valid {
		user.RefreshToken = &refreshToken.String
	}
	if refreshTokenExpiresAt.Valid {
		if expiresAt, parseErr := time.Parse(time.RFC3339, refreshTokenExpiresAt.String); parseErr == nil {
			user.RefreshTokenExpiresAt = &expiresAt
		}
	}

	return user, nil
}

func (r *userRepository) VerifyEmail(ctx context.Context, userID uuid.UUID) error {
	query := `
        UPDATE users
        SET email_verified = TRUE, verification_token = NULL, verification_token_expires_at = NULL, updated_at = NOW()
        WHERE id = $1
    `

	_, err := r.db.ExecContext(ctx, query, userID.String())
	return err
}
