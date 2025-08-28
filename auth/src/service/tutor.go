package service

import (
	"context"
	"errors"
	"github.com/mohammad-rababah/AI_school/auth/src/model/db"
	"github.com/mohammad-rababah/AI_school/auth/src/model/request"
	"github.com/mohammad-rababah/AI_school/auth/src/repo"
	"github.com/mohammad-rababah/AI_school/auth/src/util"
	"golang.org/x/crypto/bcrypt"
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
	tutorRepo repo.TutorRepo
}

func (s *tutorService) Init(ctx context.Context, req *request.InitRequest) error {
	emailChan := make(chan repo.ChanResult[bool], 1)
	phoneChan := make(chan repo.ChanResult[bool], 1)
	s.tutorRepo.IsEmailExists(ctx, req.Email, emailChan)
	s.tutorRepo.IsPhoneExists(ctx, req.Phone, phoneChan)
	emailResult := <-emailChan
	phoneResult := <-phoneChan
	close(emailChan)
	close(phoneChan)
	if emailResult.Error != nil {
		return emailResult.Error
	}
	if phoneResult.Error != nil {
		return phoneResult.Error
	}
	if emailResult.Data {
		return errors.New("email already registered")
	}
	if phoneResult.Data {
		return errors.New("phone already registered")
	}
	resultChan := make(chan repo.ChanResult[db.Tutor], 1)
	tutor := db.Tutor{
		Email:  req.Email,
		Phone:  req.Phone,
		Status: db.TutorStatusPending,
	}
	s.tutorRepo.CreateTutor(ctx, tutor, resultChan)
	createResult := <-resultChan
	close(resultChan)
	if createResult.Error != nil {
		return createResult.Error
	}
	return nil
}
func (s *tutorService) VerifyEmail(ctx context.Context, req *request.VerifyEmailRequest) error {
	return nil
}
func (s *tutorService) VerifyPhone(ctx context.Context, req *request.VerifyPhoneRequest) error {
	return nil
}
func (s *tutorService) Register(ctx context.Context, req *request.RegisterRequest) error {
	emailChan := make(chan repo.ChanResult[bool], 1)
	phoneChan := make(chan repo.ChanResult[bool], 1)
	s.tutorRepo.IsEmailExists(ctx, req.Email, emailChan)
	s.tutorRepo.IsPhoneExists(ctx, req.Phone, phoneChan)
	emailResult := <-emailChan
	phoneResult := <-phoneChan
	close(emailChan)
	close(phoneChan)
	if emailResult.Error != nil {
		return emailResult.Error
	}
	if phoneResult.Error != nil {
		return phoneResult.Error
	}
	if emailResult.Data {
		return errors.New("email already registered")
	}
	if phoneResult.Data {
		return errors.New("phone already registered")
	}
	// Hash the password using bcrypt
	hashedPasswordBytes, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	hashedPassword := string(hashedPasswordBytes)
	resultChan := make(chan repo.ChanResult[db.Tutor], 1)
	tutor := db.Tutor{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		Phone:     req.Phone,
		Password:  hashedPassword,
		Status:    db.TutorStatusPending,
	}
	s.tutorRepo.CreateTutor(ctx, tutor, resultChan)
	createResult := <-resultChan
	close(resultChan)
	if createResult.Error != nil {
		return createResult.Error
	}
	return nil
}

func (s *tutorService) Login(ctx context.Context, req *request.LoginRequest) error {
	resultChan := make(chan repo.ChanResult[*db.Tutor], 1)
	s.tutorRepo.GetTutorByEmail(ctx, req.EmailOrPhone, resultChan)
	getResult := <-resultChan
	close(resultChan)
	if getResult.Error != nil || getResult.Data == nil {
		return errors.New("invalid credentials")
	}
	if getResult.Data.Password != req.Password {
		return errors.New("invalid credentials")
	}
	_, err := util.GenerateJWT(getResult.Data.ID)
	return err
}
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
func NewTutorService(tutorRepo repo.TutorRepo) TutorService {
	return &tutorService{tutorRepo: tutorRepo}
}
