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

type StudentService interface {
	Register(ctx context.Context, req *request.StudentRegisterRequest) error
	Verify(ctx context.Context, req *request.StudentVerifyRequest) error
	Login(ctx context.Context, req *request.StudentLoginRequest) (string, string, *db.Student, error)
	Logout(ctx context.Context, userID string) error
	GetSessions(ctx context.Context, userID string) ([]string, error)
	DeleteSession(ctx context.Context, req *request.StudentDeleteSessionRequest) error
	PasswordResetRequest(ctx context.Context, req *request.StudentPasswordResetRequest) error
	PasswordResetConfirm(ctx context.Context, req *request.StudentPasswordResetConfirmRequest) error
	GetProfile(ctx context.Context, userID string) (*db.Student, error)
	RefreshTokens(refreshToken string) (string, string, error)
}

type studentService struct {
	repo repo.StudentRepo
}

func NewStudentService(repo repo.StudentRepo) StudentService {
	return &studentService{repo: repo}
}

func (s *studentService) Register(ctx context.Context, req *request.StudentRegisterRequest) error {
	if req.Email == "" && req.Phone == "" {
		return errors.NewAppError("email or phone is required", "")
	}
	if req.Email != "" {
		emailChan := make(chan repo.ChanResult[bool], 1)
		s.repo.IsEmailExists(ctx, req.Email, emailChan)
		emailResult := <-emailChan
		close(emailChan)
		if emailResult.Error != nil {
			return errors.NewAppError("internal error", emailResult.Error.Error())
		}
		if emailResult.Data {
			return errors.NewAppError("email already registered", "")
		}
	}
	if req.Phone != "" {
		phoneChan := make(chan repo.ChanResult[bool], 1)
		s.repo.IsPhoneExists(ctx, req.Phone, phoneChan)
		phoneResult := <-phoneChan
		close(phoneChan)
		if phoneResult.Error != nil {
			return errors.NewAppError("internal error", phoneResult.Error.Error())
		}
		if phoneResult.Data {
			return errors.NewAppError("phone already registered", "")
		}
	}
	hashedPasswordBytes, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.NewAppError("internal error", err.Error())
	}
	hashedPassword := string(hashedPasswordBytes)
	student := db.Student{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		Phone:     req.Phone,
		Password:  hashedPassword,
		Status:    db.StudentStatusPending,
	}
	resultChan := make(chan repo.ChanResult[db.Student], 1)
	s.repo.CreateStudent(ctx, student, resultChan)
	createResult := <-resultChan
	close(resultChan)
	if createResult.Error != nil {
		return errors.NewAppError("internal error", createResult.Error.Error())
	}
	return nil
}

func (s *studentService) Verify(ctx context.Context, req *request.StudentVerifyRequest) error {
	if req.EmailOrPhone == "" {
		return errors.NewAppError("email_or_phone is required", "")
	}
	if req.OTP == "" {
		return errors.NewAppError("verification code is required", "")
	}
	if req.OTP == "0000" {
		var studentChan = make(chan repo.ChanResult[*db.Student], 1)
		if helper.IsEmail(req.EmailOrPhone) {
			s.repo.GetStudentByEmail(ctx, req.EmailOrPhone, studentChan)
		} else if helper.IsPhone(req.EmailOrPhone) {
			s.repo.GetStudentByPhone(ctx, req.EmailOrPhone, studentChan)
		} else {
			return errors.NewAppError("invalid email or phone", "")
		}
		studentResult := <-studentChan
		close(studentChan)
		if studentResult.Error != nil || studentResult.Data == nil {
			return errors.NewAppError("student not found", "")
		}
		student := studentResult.Data
		student.Status = db.StudentStatusVerified
		updateChan := make(chan repo.ChanResult[db.Student], 1)
		s.repo.UpdateStudent(ctx, *student, updateChan)
		updateResult := <-updateChan
		close(updateChan)
		if updateResult.Error != nil {
			return errors.NewAppError("internal error", updateResult.Error.Error())
		}
		return nil
	}
	return errors.NewAppError("invalid verification code", "")
}

func (s *studentService) Login(ctx context.Context, req *request.StudentLoginRequest) (string, string, *db.Student, error) {
	var studentChan = make(chan repo.ChanResult[*db.Student], 1)
	if helper.IsEmail(req.EmailOrPhone) {
		s.repo.GetStudentByEmail(ctx, req.EmailOrPhone, studentChan)
	} else if helper.IsPhone(req.EmailOrPhone) {
		s.repo.GetStudentByPhone(ctx, req.EmailOrPhone, studentChan)
	} else {
		return "", "", nil, errors.NewAppError("invalid email or phone", "")
	}
	studentResult := <-studentChan
	close(studentChan)
	if studentResult.Error != nil || studentResult.Data == nil {
		return "", "", nil, errors.NewAppError("invalid credentials", "")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(studentResult.Data.Password), []byte(req.Password)); err != nil {
		return "", "", nil, errors.NewAppError("invalid credentials", "")
	}
	accessToken, err := util.GenerateJWT(studentResult.Data.ID)
	if err != nil {
		return "", "", nil, errors.NewAppError("internal error", err.Error())
	}
	refreshToken, err := util.GenerateJWT(studentResult.Data.ID)
	if err != nil {
		return "", "", nil, errors.NewAppError("internal error", err.Error())
	}
	return accessToken, refreshToken, studentResult.Data, nil
}

func (s *studentService) Logout(ctx context.Context, userID string) error { return nil }
func (s *studentService) GetSessions(ctx context.Context, userID string) ([]string, error) {
	return []string{}, nil
}
func (s *studentService) DeleteSession(ctx context.Context, req *request.StudentDeleteSessionRequest) error {
	return nil
}
func (s *studentService) PasswordResetRequest(ctx context.Context, req *request.StudentPasswordResetRequest) error {
	return nil
}
func (s *studentService) PasswordResetConfirm(ctx context.Context, req *request.StudentPasswordResetConfirmRequest) error {
	return nil
}
func (s *studentService) GetProfile(ctx context.Context, userID string) (*db.Student, error) {
	var id uint
	_, err := fmt.Sscanf(userID, "%d", &id)
	if err != nil {
		return nil, errors.NewAppError("invalid user id", err.Error())
	}
	studentChan := make(chan repo.ChanResult[*db.Student], 1)
	s.repo.GetStudentByID(ctx, id, studentChan)
	studentResult := <-studentChan
	close(studentChan)
	if studentResult.Error != nil || studentResult.Data == nil {
		return nil, errors.NewAppError("student not found", "")
	}
	return studentResult.Data, nil
}
func (s *studentService) RefreshTokens(refreshToken string) (string, string, error) {
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
