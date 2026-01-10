package service

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"g-auth/internal/domain"
	"g-auth/internal/repository"
	"g-auth/pkg/jwt"
	"g-auth/pkg/password"
)

type AuthService struct {
	userRepo   repository.UserRepository
	jwtManager *jwt.JWTManager
}

func NewAuthService(userRepo repository.UserRepository, jwtManager *jwt.JWTManager) *AuthService {
	return &AuthService{
		userRepo:   userRepo,
		jwtManager: jwtManager,
	}
}

func (s *AuthService) Register(ctx context.Context, req *domain.RegisterRequest) (*domain.AuthResponse, error) {
	// check if user already exists
	existingUser, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil && !errors.Is(err, domain.ErrUserNotFound) {
		return nil, err
	}
	if existingUser != nil {
		return nil, domain.ErrUserAlreadyExists
	}

	// hash password
	hashedPassword, err := password.Hash(req.Password)
	if err != nil {
		return nil, err
	}

	// create user
	user := &domain.User{
		Email:    req.Email,
		Password: hashedPassword,
		Name:     req.Name,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// generate token
	token, err := s.jwtManager.Generate(user.ID, user.Email)
	if err != nil {
		return nil, err
	}

	return &domain.AuthResponse{
		Token: token,
		User:  *user,
	}, nil

}

func (s *AuthService) Login(ctx context.Context, req *domain.LoginRequest) (*domain.AuthResponse, error) {
	// get user by email
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}

	// verify password
	if !password.Verify(req.Password, user.Password) {
		return nil, domain.ErrInvalidCredentials
	}

	// generate token
	token, err := s.jwtManager.Generate(user.ID, user.Email)
	if err != nil {
		return nil, err
	}

	return &domain.AuthResponse{
		Token: token,
		User:  *user,
	}, nil
}

func (s *AuthService) GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return s.userRepo.GetByID(ctx, id)
}
