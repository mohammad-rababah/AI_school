package service

import (
	"context"
	"learing_project/auth/src/model/request"
)

// TutorService defines public methods for tutor business logic
type TutorService interface {
	Init(ctx context.Context, req *request.InitRequest) error
	VerifyEmail(ctx context.Context, req *request.VerifyEmailRequest) error
	VerifyPhone(ctx context.Context, req *request.VerifyPhoneRequest) error
	Register(ctx context.Context, req *request.RegisterRequest) error
	Login(ctx context.Context, req *request.LoginRequest) error
	TokenRefresh(ctx context.Context, req *request.TokenRefreshRequest) error
	Logout(ctx context.Context, userID string) error
	GetSessions(ctx context.Context, userID string) ([]string, error)
	DeleteSession(ctx context.Context, req *request.DeleteSessionRequest) error
	PasswordResetRequest(ctx context.Context, req *request.PasswordResetRequest) error
	PasswordResetConfirm(ctx context.Context, req *request.PasswordResetConfirmRequest) error
	GetStatus(ctx context.Context, userID string) (string, error)
}

// tutorService is the private implementation
type tutorService struct {
	// add any dependencies here (e.g. repo, logger)
}

func (s *tutorService) Init(ctx context.Context, req *request.InitRequest) error { return nil }
func (s *tutorService) VerifyEmail(ctx context.Context, req *request.VerifyEmailRequest) error {
	return nil
}
func (s *tutorService) VerifyPhone(ctx context.Context, req *request.VerifyPhoneRequest) error {
	return nil
}
func (s *tutorService) Register(ctx context.Context, req *request.RegisterRequest) error { return nil }
func (s *tutorService) Login(ctx context.Context, req *request.LoginRequest) error       { return nil }
func (s *tutorService) TokenRefresh(ctx context.Context, req *request.TokenRefreshRequest) error {
	return nil
}
func (s *tutorService) Logout(ctx context.Context, userID string) error { return nil }
func (s *tutorService) GetSessions(ctx context.Context, userID string) ([]string, error) {
	return []string{}, nil
}
func (s *tutorService) DeleteSession(ctx context.Context, req *request.DeleteSessionRequest) error {
	return nil
}
func (s *tutorService) PasswordResetRequest(ctx context.Context, req *request.PasswordResetRequest) error {
	return nil
}
func (s *tutorService) PasswordResetConfirm(ctx context.Context, req *request.PasswordResetConfirmRequest) error {
	return nil
}
func (s *tutorService) GetStatus(ctx context.Context, userID string) (string, error) { return "", nil }

// NewTutorService returns the public interface
func NewTutorService() TutorService {
	return &tutorService{}
}
