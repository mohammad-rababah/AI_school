package service

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mohammad-rababah/AI_school/auth/src/errors"
	"github.com/mohammad-rababah/AI_school/auth/src/helper"
	"github.com/mohammad-rababah/AI_school/auth/src/model/db"
	"github.com/mohammad-rababah/AI_school/auth/src/model/request"
	"github.com/mohammad-rababah/AI_school/auth/src/repo"
	"github.com/mohammad-rababah/AI_school/auth/src/util"
	"golang.org/x/crypto/bcrypt"
)

// TutorService defines public methods for tutor business logic
type TutorService interface {
	Verify(ctx context.Context, req *request.VerifyRequest) error
	Register(ctx context.Context, req *request.RegisterRequest) error
	Login(ctx context.Context, req *request.LoginRequest) (string, string, *db.Tutor, error)
	Logout(ctx context.Context, userID string) error
	GetSessions(ctx context.Context, userID string) ([]string, error)
	DeleteSession(ctx context.Context, req *request.DeleteSessionRequest) error
	PasswordResetRequest(ctx context.Context, req *request.PasswordResetRequest) error
	PasswordResetConfirm(ctx context.Context, req *request.PasswordResetConfirmRequest) error
	GetProfile(ctx context.Context, userID string) (*db.Tutor, error)
	RefreshTokens(refreshToken string) (string, string, error)
}

// tutorService is the private implementation
type tutorService struct {
	tutorRepo repo.TutorRepo
}

func (s *tutorService) Verify(ctx context.Context, req *request.VerifyRequest) error {
	if req.EmailOrPhone == "" {
		return errors.NewAppError("email_or_phone is required", "")
	}
	if req.OTP == "" {
		return errors.NewAppError("verification code is required", "")
	}
	if req.OTP == "0000" {
		var tutorChan = make(chan repo.ChanResult[*db.Tutor], 1)
		if helper.IsEmail(req.EmailOrPhone) {
			s.tutorRepo.GetTutorByEmail(ctx, req.EmailOrPhone, tutorChan)
		} else if helper.IsPhone(req.EmailOrPhone) {
			s.tutorRepo.GetTutorByPhone(ctx, req.EmailOrPhone, tutorChan)
		} else {
			return errors.NewAppError("invalid email or phone", "")
		}
		tutorResult := <-tutorChan
		close(tutorChan)
		if tutorResult.Error != nil || tutorResult.Data == nil {
			return errors.NewAppError("tutor not found", "")
		}
		tutor := tutorResult.Data
		tutor.Status = db.TutorStatusOnboarding // Change status to ONBOARDING
		updateChan := make(chan repo.ChanResult[db.Tutor], 1)
		s.tutorRepo.UpdateTutor(ctx, *tutor, updateChan)
		updateResult := <-updateChan
		close(updateChan)
		if updateResult.Error != nil {
			return errors.NewAppError("internal error", updateResult.Error.Error())
		}
		return nil
	}
	return errors.NewAppError("invalid verification code", "")
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
		return errors.NewAppError("internal error", emailResult.Error.Error())
	}
	if phoneResult.Error != nil {
		return errors.NewAppError("internal error", phoneResult.Error.Error())
	}
	if emailResult.Data {
		return errors.NewAppError("email already registered", "")
	}
	if phoneResult.Data {
		return errors.NewAppError("phone already registered", "")
	}
	// Hash the password using bcrypt
	hashedPasswordBytes, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.NewAppError("internal error", err.Error())
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
		return errors.NewAppError("internal error", createResult.Error.Error())
	}
	return nil
}

func (s *tutorService) Login(ctx context.Context, req *request.LoginRequest) (string, string, *db.Tutor, error) {
	resultChan := make(chan repo.ChanResult[*db.Tutor], 1)
	s.tutorRepo.GetTutorByEmail(ctx, req.EmailOrPhone, resultChan)
	getResult := <-resultChan
	close(resultChan)
	if getResult.Error != nil || getResult.Data == nil {
		return "", "", nil, errors.NewAppError("invalid credentials", "")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(getResult.Data.Password), []byte(req.Password)); err != nil {
		return "", "", nil, errors.NewAppError("invalid credentials", "")
	}
	accessToken, err := util.GenerateJWT(getResult.Data.ID)
	if err != nil {
		return "", "", nil, errors.NewAppError("internal error", err.Error())
	}
	refreshToken, err := util.GenerateJWT(getResult.Data.ID) // For MVP, reuse same logic
	if err != nil {
		return "", "", nil, errors.NewAppError("internal error", err.Error())
	}
	return accessToken, refreshToken, getResult.Data, nil
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
func (s *tutorService) GetProfile(ctx context.Context, userID string) (*db.Tutor, error) {
	var id uint
	_, err := fmt.Sscanf(userID, "%d", &id)
	if err != nil {
		return nil, errors.NewAppError("invalid user id", err.Error())
	}
	resultChan := make(chan repo.ChanResult[*db.Tutor], 1)
	s.tutorRepo.GetTutorByID(ctx, id, resultChan)
	getResult := <-resultChan
	close(resultChan)
	if getResult.Error != nil || getResult.Data == nil {
		return nil, errors.NewAppError("tutor not found", "")
	}
	return getResult.Data, nil
}
func (s *tutorService) RefreshTokens(refreshToken string) (string, string, error) {
	if refreshToken == "" {
		return "", "", errors.NewAppError("refresh token is required", "")
	}
	token, err := util.ValidateJWT(refreshToken)
	if err != nil || !token.Valid {
		return "", "", errors.NewAppError("invalid refresh token", err.Error())
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", errors.NewAppError("invalid token claims", "")
	}
	userIDFloat, ok := claims["user_id"].(float64)
	if !ok {
		return "", "", errors.NewAppError("invalid user_id in token", "")
	}
	userID := uint(userIDFloat)
	newAccessToken, err := util.GenerateJWT(userID)
	if err != nil {
		return "", "", errors.NewAppError("failed to generate access token", err.Error())
	}
	// For MVP, reuse the same refresh token
	return newAccessToken, refreshToken, nil
}

// NewTutorService returns the public interface
func NewTutorService(tutorRepo repo.TutorRepo) TutorService {
	return &tutorService{tutorRepo: tutorRepo}
}
