package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/mohammad-rababah/AI_school/auth/src/middleware"
	"github.com/mohammad-rababah/AI_school/auth/src/model/request"
	"github.com/mohammad-rababah/AI_school/auth/src/model/response"
	"github.com/mohammad-rababah/AI_school/auth/src/service"
	"net/http"
)

type StudentController interface {
	Register(c *gin.Context)
	Verify(c *gin.Context)
	Login(c *gin.Context)
	Logout(c *gin.Context)
	GetSessions(c *gin.Context)
	DeleteSession(c *gin.Context)
	PasswordResetRequest(c *gin.Context)
	PasswordResetConfirm(c *gin.Context)
	GetProfile(c *gin.Context)
	TokenRefresh(c *gin.Context)
	GetStatus(c *gin.Context)
}

type studentController struct {
	service service.StudentService
}

// Register godoc
// @Summary      Register student
// @Description  Registers a new student with provided details
// @Tags         student
// @Accept       json
// @Produce      json
// @Param        request body request.StudentRegisterRequest true "Register request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /student/auth/register [post]
func (s *studentController) Register(c *gin.Context) {
	var req request.StudentRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := s.service.Register(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "student registered"})
}

// Verify godoc
// @Summary      Verify student contact (email or phone)
// @Description  Verifies the contact with OTP
// @Tags         student
// @Accept       json
// @Produce      json
// @Param        request body request.StudentVerifyRequest true "Verify request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /student/auth/verify [post]
func (s *studentController) Verify(c *gin.Context) {
	var req request.StudentVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := s.service.Verify(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "verify contact"})
}

// Login godoc
// @Summary      Student login
// @Description  Authenticates student and returns JWT tokens and profile
// @Tags         student
// @Accept       json
// @Produce      json
// @Param        request body request.StudentLoginRequest true "Login request"
// @Success      200 {object} response.StudentLoginWithProfileResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /student/auth/login [post]
func (s *studentController) Login(c *gin.Context) {
	var req request.StudentLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	accessToken, refreshToken, profile, err := s.service.Login(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{Error: err.Error()})
		return
	}
	resp := response.StudentLoginWithProfileResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Profile: response.StudentProfileResponse{
			ID:        profile.ID,
			FirstName: profile.FirstName,
			LastName:  profile.LastName,
			Email:     profile.Email,
			Phone:     profile.Phone,
			Status:    string(profile.Status),
		},
	}
	c.JSON(http.StatusOK, resp)
}

// Logout godoc
// @Summary      Student logout
// @Description  Logs out the student and invalidates session
// @Tags         student
// @Produce      json
// @Success      200 {object} response.GenericResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /student/auth/logout [post]
func (s *studentController) Logout(c *gin.Context) {
	userID := c.GetString("userID")
	if err := s.service.Logout(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "logout"})
}

// GetSessions godoc
// @Summary      Get active sessions
// @Description  Returns all active sessions for the student
// @Tags         student
// @Produce      json
// @Success      200 {object} response.SessionsResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /student/auth/sessions [get]
func (s *studentController) GetSessions(c *gin.Context) {
	userID := c.GetString("userID")
	sessions, err := s.service.GetSessions(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.SessionsResponse{Sessions: sessions})
}

// DeleteSession godoc
// @Summary      Delete session
// @Description  Deletes a specific session by ID
// @Tags         student
// @Produce      json
// @Param        id path string true "Session ID"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /student/auth/sessions/{id} [delete]
func (s *studentController) DeleteSession(c *gin.Context) {
	var req request.StudentDeleteSessionRequest
	if err := c.ShouldBindUri(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := s.service.DeleteSession(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "delete session"})
}

// PasswordResetRequest godoc
// @Summary      Request password reset
// @Description  Requests a password reset for student
// @Tags         student
// @Accept       json
// @Produce      json
// @Param        request body request.StudentPasswordResetRequest true "Password reset request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /student/auth/password/reset/request [post]
func (s *studentController) PasswordResetRequest(c *gin.Context) {
	var req request.StudentPasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := s.service.PasswordResetRequest(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "password reset request"})
}

// PasswordResetConfirm godoc
// @Summary      Confirm password reset
// @Description  Confirms password reset with OTP and new password
// @Tags         student
// @Accept       json
// @Produce      json
// @Param        request body request.StudentPasswordResetConfirmRequest true "Password reset confirm request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /student/auth/password/reset/confirm [post]
func (s *studentController) PasswordResetConfirm(c *gin.Context) {
	var req request.StudentPasswordResetConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := s.service.PasswordResetConfirm(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "password reset confirm"})
}

// GetProfile godoc
// @Summary      Get student profile
// @Description  Returns the current profile of the student
// @Tags         student
// @Produce      json
// @Success      200 {object} response.StudentProfileResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /student/auth/profile [get]
func (s *studentController) GetProfile(c *gin.Context) {
	userID := c.GetString("userID")
	profile, err := s.service.GetProfile(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	resp := response.StudentProfileResponse{
		ID:        profile.ID,
		FirstName: profile.FirstName,
		LastName:  profile.LastName,
		Email:     profile.Email,
		Phone:     profile.Phone,
		Status:    string(profile.Status),
	}
	c.JSON(http.StatusOK, resp)
}

// TokenRefresh godoc
// @Summary      Refresh student tokens
// @Description  Refreshes the access and refresh tokens for the student
// @Tags         student
// @Accept       json
// @Produce      json
// @Param        request body request.StudentTokenRefreshRequest true "Token refresh request"
// @Success      200 {object} response.LoginResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /student/auth/token/refresh [post]
func (s *studentController) TokenRefresh(c *gin.Context) {
	var req request.StudentTokenRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "Missing or invalid refresh token"})
		return
	}
	accessToken, refreshToken, err := s.service.RefreshTokens(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// GetStatus godoc
// @Summary      Get student status
// @Description  Returns the current status of the student
// @Tags         student
// @Produce      json
// @Success      200 {object} response.StatusResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /student/auth/status [get]
func (s *studentController) GetStatus(c *gin.Context) {
	userID := c.GetString("userID")
	profile, err := s.service.GetProfile(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.StatusResponse{Status: string(profile.Status)})
}

func NewStudentController(s service.StudentService) StudentController {
	return &studentController{service: s}
}

func InitStudentAPIs(rg *gin.RouterGroup, s service.StudentService) {
	ctrl := NewStudentController(s)
	student := rg.Group("student/auth")
	{
		student.POST("/register", ctrl.Register)
		student.POST("/verify", ctrl.Verify)
		student.POST("/login", ctrl.Login)
		student.POST("/password/reset/request", ctrl.PasswordResetRequest)
		student.POST("/token/refresh", ctrl.TokenRefresh)
	}
	studentAuth := student.Group("").Use(middleware.JWTAuthMiddleware())
	{
		studentAuth.POST("/logout", ctrl.Logout)
		studentAuth.GET("/sessions", ctrl.GetSessions)
		studentAuth.DELETE("/sessions/:id", ctrl.DeleteSession)
		studentAuth.POST("/password/reset/confirm", ctrl.PasswordResetConfirm)
		studentAuth.GET("/profile", ctrl.GetProfile)
		studentAuth.GET("/status", ctrl.GetStatus)
	}
}
