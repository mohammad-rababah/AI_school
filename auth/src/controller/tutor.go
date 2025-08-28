package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/mohammad-rababah/AI_school/auth/src/middleware"
	"github.com/mohammad-rababah/AI_school/auth/src/model/request"
	"github.com/mohammad-rababah/AI_school/auth/src/model/response"
	"github.com/mohammad-rababah/AI_school/auth/src/service"
	"net/http"
)

// TutorController defines public methods for tutor APIs
type TutorController interface {
	Init(c *gin.Context)
	VerifyEmail(c *gin.Context)
	VerifyPhone(c *gin.Context)
	Register(c *gin.Context)
	Login(c *gin.Context)
	TokenRefresh(c *gin.Context)
	Logout(c *gin.Context)
	GetSessions(c *gin.Context)
	DeleteSession(c *gin.Context)
	PasswordResetRequest(c *gin.Context)
	PasswordResetConfirm(c *gin.Context)
	GetStatus(c *gin.Context)
}

// tutorController is the private implementation
type tutorController struct {
	service service.TutorService
}

// Init godoc
// @Summary      Initialize tutor registration
// @Description  Checks if email/phone are available and creates a preliminary tutor record
// @Tags         tutor
// @Accept       json
// @Produce      json
// @Param        request body request.InitRequest true "Init request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /tutor/auth/init [post]
func (t *tutorController) Init(c *gin.Context) {
	var req request.InitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.Init(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "tutor init"})
}

// VerifyEmail godoc
// @Summary      Verify tutor email
// @Description  Verifies the email with OTP
// @Tags         tutor
// @Accept       json
// @Produce      json
// @Param        request body request.VerifyEmailRequest true "Verify email request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /tutor/auth/verify/email [post]
func (t *tutorController) VerifyEmail(c *gin.Context) {
	var req request.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.VerifyEmail(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "verify email"})
}

// VerifyPhone godoc
// @Summary      Verify tutor phone
// @Description  Verifies the phone with OTP
// @Tags         tutor
// @Accept       json
// @Produce      json
// @Param        request body request.VerifyPhoneRequest true "Verify phone request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /tutor/auth/verify/phone [post]
func (t *tutorController) VerifyPhone(c *gin.Context) {
	var req request.VerifyPhoneRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.VerifyPhone(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "verify phone"})
}

// Register godoc
// @Summary      Register tutor
// @Description  Registers a new tutor with provided details
// @Tags         tutor
// @Accept       json
// @Produce      json
// @Param        request body request.RegisterRequest true "Register request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /tutor/auth/register [post]
func (t *tutorController) Register(c *gin.Context) {
	var req request.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.Register(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "register"})
}

// Login godoc
// @Summary      Tutor login
// @Description  Authenticates tutor and returns JWT tokens
// @Tags         tutor
// @Accept       json
// @Produce      json
// @Param        request body request.LoginRequest true "Login request"
// @Success      200 {object} response.LoginResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Router       /tutor/auth/login [post]
func (t *tutorController) Login(c *gin.Context) {
	var req request.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.Login(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.LoginResponse{AccessToken: "", RefreshToken: ""}) // stub
}

// TokenRefresh godoc
// @Summary      Refresh JWT token
// @Description  Refreshes access and refresh tokens
// @Tags         tutor
// @Accept       json
// @Produce      json
// @Param        request body request.TokenRefreshRequest true "Token refresh request"
// @Success      200 {object} response.LoginResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Router       /tutor/auth/token/refresh [post]
func (t *tutorController) TokenRefresh(c *gin.Context) {
	var req request.TokenRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.TokenRefresh(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.LoginResponse{AccessToken: "", RefreshToken: ""}) // stub
}

// Logout godoc
// @Summary      Tutor logout
// @Description  Logs out the tutor and invalidates session
// @Tags         tutor
// @Produce      json
// @Success      200 {object} response.GenericResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /tutor/auth/logout [post]
func (t *tutorController) Logout(c *gin.Context) {
	userID := c.GetString("userID") // placeholder, should be extracted from context/session
	if err := t.service.Logout(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "logout"})
}

// GetSessions godoc
// @Summary      Get active sessions
// @Description  Returns all active sessions for the tutor
// @Tags         tutor
// @Produce      json
// @Success      200 {object} response.SessionsResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /tutor/auth/sessions [get]
func (t *tutorController) GetSessions(c *gin.Context) {
	userID := c.GetString("userID") // placeholder
	sessions, err := t.service.GetSessions(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.SessionsResponse{Sessions: sessions})
}

// DeleteSession godoc
// @Summary      Delete session
// @Description  Deletes a specific session by ID
// @Tags         tutor
// @Produce      json
// @Param        id path string true "Session ID"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /tutor/auth/sessions/{id} [delete]
func (t *tutorController) DeleteSession(c *gin.Context) {
	var req request.DeleteSessionRequest
	if err := c.ShouldBindUri(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.DeleteSession(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "delete session"})
}

// PasswordResetRequest godoc
// @Summary      Request password reset
// @Description  Requests a password reset for tutor
// @Tags         tutor
// @Accept       json
// @Produce      json
// @Param        request body request.PasswordResetRequest true "Password reset request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /tutor/auth/password/reset/request [post]
func (t *tutorController) PasswordResetRequest(c *gin.Context) {
	var req request.PasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.PasswordResetRequest(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "password reset request"})
}

// PasswordResetConfirm godoc
// @Summary      Confirm password reset
// @Description  Confirms password reset with OTP and new password
// @Tags         tutor
// @Accept       json
// @Produce      json
// @Param        request body request.PasswordResetConfirmRequest true "Password reset confirm request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /tutor/auth/password/reset/confirm [post]
func (t *tutorController) PasswordResetConfirm(c *gin.Context) {
	var req request.PasswordResetConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.PasswordResetConfirm(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "password reset confirm"})
}

// GetStatus godoc
// @Summary      Get tutor status
// @Description  Returns the current status of the tutor
// @Tags         tutor
// @Produce      json
// @Success      200 {object} response.StatusResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /tutor/auth/status [get]
func (t *tutorController) GetStatus(c *gin.Context) {
	userID := c.GetString("userID") // placeholder
	status, err := t.service.GetStatus(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.StatusResponse{Status: status})
}

// NewTutorController returns the public interface
func NewTutorController(s service.TutorService) TutorController {
	return &tutorController{service: s}
}

// InitTutorAPIs registers tutor routes to the Gin router group
func InitTutorAPIs(rg *gin.RouterGroup, s service.TutorService) {
	ctrl := NewTutorController(s)
	// Public endpoints
	tutor := rg.Group("tutor/auth")
	{
		tutor.POST("/init", ctrl.Init)
		tutor.POST("/verify/email", ctrl.VerifyEmail)
		tutor.POST("/verify/phone", ctrl.VerifyPhone)
		tutor.POST("/register", ctrl.Register)
		tutor.POST("/login", ctrl.Login)
		tutor.POST("/token/refresh", ctrl.TokenRefresh)
		tutor.POST("/password/reset/request", ctrl.PasswordResetRequest)
	}
	// Protected endpoints with JWT middleware
	tutorAuth := tutor.Group("").Use(middleware.JWTAuthMiddleware())
	{
		tutorAuth.POST("/logout", ctrl.Logout)
		tutorAuth.GET("/sessions", ctrl.GetSessions)
		tutorAuth.DELETE("/sessions/:id", ctrl.DeleteSession)
		tutorAuth.POST("/password/reset/confirm", ctrl.PasswordResetConfirm)
		tutorAuth.GET("/status", ctrl.GetStatus)
	}
}
