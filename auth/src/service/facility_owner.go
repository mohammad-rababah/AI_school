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

type FacilityOwnerService interface {
	Register(ctx context.Context, req *request.FacilityOwnerRegisterRequest) error
	VerifyEmail(ctx context.Context, req *request.FacilityOwnerVerifyEmailRequest) error
	VerifyPhone(ctx context.Context, req *request.FacilityOwnerVerifyPhoneRequest) error
	Login(ctx context.Context, req *request.FacilityOwnerLoginRequest) (string, string, *db.FacilityOwner, error)
	Logout(ctx context.Context, userID string) error
	GetSessions(ctx context.Context, userID string) ([]string, error)
	DeleteSession(ctx context.Context, req *request.FacilityOwnerDeleteSessionRequest) error
	PasswordResetRequest(ctx context.Context, req *request.FacilityOwnerPasswordResetRequest) error
	PasswordResetConfirm(ctx context.Context, req *request.FacilityOwnerPasswordResetConfirmRequest) error
	GetProfile(ctx context.Context, userID string) (*db.FacilityOwner, error)
	RefreshTokens(refreshToken string) (string, string, error)
	OnboardingDocuments(ctx context.Context, req *request.FacilityOwnerOnboardingDocumentsRequest) error
	GetStatus(ctx context.Context, userID string) (string, error)
}

type facilityOwnerService struct {
	repo         repo.FacilityOwnerRepo
	facilityRepo repo.FacilityRepo
}

func NewFacilityOwnerService(repo repo.FacilityOwnerRepo, facilityRepo repo.FacilityRepo) FacilityOwnerService {
	return &facilityOwnerService{repo: repo, facilityRepo: facilityRepo}
}

func (s *facilityOwnerService) Register(ctx context.Context, req *request.FacilityOwnerRegisterRequest) error {
	if req.Email == "" || req.Phone == "" {
		return errors.NewAppError("email and phone are required", "")
	}
	emailChan := make(chan repo.ChanResult[bool], 1)
	phoneChan := make(chan repo.ChanResult[bool], 1)
	s.repo.IsEmailExists(ctx, req.Email, emailChan)
	s.repo.IsPhoneExists(ctx, req.Phone, phoneChan)
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
	hashedPasswordBytes, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.NewAppError("internal error", err.Error())
	}
	hashedPassword := string(hashedPasswordBytes)
	owner := db.FacilityOwner{
		Email:    req.Email,
		Phone:    req.Phone,
		Password: hashedPassword,
		Role:     "facility_owner",
		Status:   db.FacilityOwnerStatusPending,
	}
	resultChan := make(chan repo.ChanResult[db.FacilityOwner], 1)
	s.repo.CreateFacilityOwner(ctx, owner, resultChan)
	createResult := <-resultChan
	close(resultChan)
	if createResult.Error != nil {
		return errors.NewAppError("internal error", createResult.Error.Error())
	}
	return nil
}

func (s *facilityOwnerService) VerifyEmail(ctx context.Context, req *request.FacilityOwnerVerifyEmailRequest) error {
	if req.Email == "" || req.OTP == "" {
		return errors.NewAppError("email and otp are required", "")
	}
	ownerChan := make(chan repo.ChanResult[*db.FacilityOwner], 1)
	s.repo.GetFacilityOwnerByEmail(ctx, req.Email, ownerChan)
	ownerResult := <-ownerChan
	close(ownerChan)
	if ownerResult.Error != nil || ownerResult.Data == nil {
		return errors.NewAppError("facility owner not found", "")
	}
	if req.OTP != "0000" {
		return errors.NewAppError("invalid verification code", "")
	}
	owner := ownerResult.Data
	owner.Status = db.FacilityOwnerStatusOnboarding
	updateChan := make(chan repo.ChanResult[db.FacilityOwner], 1)
	s.repo.UpdateFacilityOwner(ctx, *owner, updateChan)
	updateResult := <-updateChan
	close(updateChan)
	if updateResult.Error != nil {
		return errors.NewAppError("internal error", updateResult.Error.Error())
	}
	return nil
}

func (s *facilityOwnerService) VerifyPhone(ctx context.Context, req *request.FacilityOwnerVerifyPhoneRequest) error {
	if req.Phone == "" || req.OTP == "" {
		return errors.NewAppError("phone and otp are required", "")
	}
	ownerChan := make(chan repo.ChanResult[*db.FacilityOwner], 1)
	s.repo.GetFacilityOwnerByPhone(ctx, req.Phone, ownerChan)
	ownerResult := <-ownerChan
	close(ownerChan)
	if ownerResult.Error != nil || ownerResult.Data == nil {
		return errors.NewAppError("facility owner not found", "")
	}
	if req.OTP != "0000" {
		return errors.NewAppError("invalid verification code", "")
	}
	owner := ownerResult.Data
	owner.Status = db.FacilityOwnerStatusOnboarding
	updateChan := make(chan repo.ChanResult[db.FacilityOwner], 1)
	s.repo.UpdateFacilityOwner(ctx, *owner, updateChan)
	updateResult := <-updateChan
	close(updateChan)
	if updateResult.Error != nil {
		return errors.NewAppError("internal error", updateResult.Error.Error())
	}
	return nil
}

func (s *facilityOwnerService) Login(ctx context.Context, req *request.FacilityOwnerLoginRequest) (string, string, *db.FacilityOwner, error) {
	var ownerChan = make(chan repo.ChanResult[*db.FacilityOwner], 1)
	if helper.IsEmail(req.EmailOrPhone) {
		s.repo.GetFacilityOwnerByEmail(ctx, req.EmailOrPhone, ownerChan)
	} else if helper.IsPhone(req.EmailOrPhone) {
		s.repo.GetFacilityOwnerByPhone(ctx, req.EmailOrPhone, ownerChan)
	} else {
		return "", "", nil, errors.NewAppError("invalid email or phone", "")
	}
	ownerResult := <-ownerChan
	close(ownerChan)
	if ownerResult.Error != nil || ownerResult.Data == nil {
		return "", "", nil, errors.NewAppError("invalid credentials", "")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(ownerResult.Data.Password), []byte(req.Password)); err != nil {
		return "", "", nil, errors.NewAppError("invalid credentials", "")
	}
	accessToken, err := util.GenerateJWT(ownerResult.Data.ID)
	if err != nil {
		return "", "", nil, errors.NewAppError("internal error", err.Error())
	}
	refreshToken, err := util.GenerateJWT(ownerResult.Data.ID)
	if err != nil {
		return "", "", nil, errors.NewAppError("internal error", err.Error())
	}
	return accessToken, refreshToken, ownerResult.Data, nil
}

func (s *facilityOwnerService) Logout(ctx context.Context, userID string) error { return nil }
func (s *facilityOwnerService) GetSessions(ctx context.Context, userID string) ([]string, error) {
	return []string{}, nil
}
func (s *facilityOwnerService) DeleteSession(ctx context.Context, req *request.FacilityOwnerDeleteSessionRequest) error {
	return nil
}
func (s *facilityOwnerService) PasswordResetRequest(ctx context.Context, req *request.FacilityOwnerPasswordResetRequest) error {
	return nil
}
func (s *facilityOwnerService) PasswordResetConfirm(ctx context.Context, req *request.FacilityOwnerPasswordResetConfirmRequest) error {
	return nil
}
func (s *facilityOwnerService) GetProfile(ctx context.Context, userID string) (*db.FacilityOwner, error) {
	var id uint
	_, err := fmt.Sscanf(userID, "%d", &id)
	if err != nil {
		return nil, errors.NewAppError("invalid user id", err.Error())
	}
	ownerChan := make(chan repo.ChanResult[*db.FacilityOwner], 1)
	s.repo.GetFacilityOwnerByID(ctx, id, ownerChan)
	ownerResult := <-ownerChan
	close(ownerChan)
	if ownerResult.Error != nil || ownerResult.Data == nil {
		return nil, errors.NewAppError("facility owner not found", "")
	}
	return ownerResult.Data, nil
}
func (s *facilityOwnerService) RefreshTokens(refreshToken string) (string, string, error) {
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
	return newAccessToken, refreshToken, nil
}
func (s *facilityOwnerService) OnboardingDocuments(ctx context.Context, req *request.FacilityOwnerOnboardingDocumentsRequest) error {
	facilityChan := make(chan repo.ChanResult[*db.Facility], 1)
	s.facilityRepo.GetFacilityByID(ctx, req.FacilityID, facilityChan)
	facilityResult := <-facilityChan
	close(facilityChan)
	if facilityResult.Error != nil || facilityResult.Data == nil {
		return errors.NewAppError("facility not found", "")
	}
	facility := facilityResult.Data
	facility.Documents = req.Documents
	facility.Status = db.FacilityStatusOnboarding
	updateChan := make(chan repo.ChanResult[db.Facility], 1)
	s.facilityRepo.UpdateFacility(ctx, *facility, updateChan)
	updateResult := <-updateChan
	close(updateChan)
	if updateResult.Error != nil {
		return errors.NewAppError("internal error", updateResult.Error.Error())
	}
	return nil
}
func (s *facilityOwnerService) GetStatus(ctx context.Context, userID string) (string, error) {
	owner, err := s.GetProfile(ctx, userID)
	if err != nil {
		return "", err
	}
	return string(owner.Status), nil
}
