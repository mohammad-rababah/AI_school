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
	Verify(c *gin.Context)
	Register(c *gin.Context)
	Login(c *gin.Context)
	Logout(c *gin.Context)
	GetSessions(c *gin.Context)
	DeleteSession(c *gin.Context)
	PasswordResetRequest(c *gin.Context)
	PasswordResetConfirm(c *gin.Context)
	GetProfile(c *gin.Context)
	TokenRefresh(c *gin.Context)
}

// tutorController is the private implementation
type tutorController struct {
	service service.TutorService
}

// Verify godoc
// @Summary      Verify tutor contact (email or phone)
// @Description  Verifies the contact with OTP
// @Tags         tutor
// @Accept       json
// @Produce      json
// @Param        request body request.VerifyRequest true "Verify request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /tutor/auth/verify [post]
func (t *tutorController) Verify(c *gin.Context) {
	var req request.VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.Verify(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "verify contact"})
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
	c.JSON(http.StatusOK, response.GenericResponse{Message: "user registered"})
}

// Login godoc
// @Summary      Tutor login
// @Description  Authenticates tutor and returns JWT tokens and profile
// @Tags         tutor
// @Accept       json
// @Produce      json
// @Param        request body request.LoginRequest true "Login request"
// @Success      200 {object} response.LoginWithProfileResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /tutor/auth/login [post]
func (t *tutorController) Login(c *gin.Context) {
	var req request.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	accessToken, refreshToken, profile, err := t.service.Login(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{Error: err.Error()})
		return
	}
	resp := response.LoginWithProfileResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Profile: response.ProfileResponse{
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
// @Summary      Tutor logout
// @Description  Logs out the tutor and invalidates session
// @Tags         tutor
// @Produce      json
// @Success      200 {object} response.GenericResponse
// @Failure      401 {object} response.ErrorResponse
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
// @Failure      401 {object} response.ErrorResponse
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
// @Failure      401 {object} response.ErrorResponse
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

// GetProfile godoc
// @Summary      Get tutor profile
// @Description  Returns the current profile of the tutor
// @Tags         tutor
// @Produce      json
// @Success      200 {object} response.ProfileResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /tutor/auth/profile [get]
func (t *tutorController) GetProfile(c *gin.Context) {
	userID := c.GetString("userID") // placeholder
	profile, err := t.service.GetProfile(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	resp := response.ProfileResponse{
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
// @Summary      Refresh tutor tokens
// @Description  Refreshes the access and refresh tokens for the tutor
// @Tags         tutor
// @Accept       json
// @Produce      json
// @Param        request body request.TokenRefreshRequest true "Token refresh request"
// @Success      200 {object} response.LoginResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /tutor/auth/token/refresh [post]
func (t *tutorController) TokenRefresh(c *gin.Context) {
	var req request.TokenRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "Missing or invalid refresh token"})
		return
	}
	accessToken, refreshToken, err := t.service.RefreshTokens(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
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
		tutor.POST("/verify", ctrl.Verify)
		tutor.POST("/register", ctrl.Register)
		tutor.POST("/login", ctrl.Login)
		tutor.POST("/password/reset/request", ctrl.PasswordResetRequest)
		tutor.POST("/token/refresh", ctrl.TokenRefresh)
	}
	// Protected endpoints with JWT middleware
	tutorAuth := tutor.Group("").Use(middleware.JWTAuthMiddleware())
	{
		tutorAuth.POST("/logout", ctrl.Logout)
		tutorAuth.GET("/sessions", ctrl.GetSessions)
		tutorAuth.DELETE("/sessions/:id", ctrl.DeleteSession)
		tutorAuth.POST("/password/reset/confirm", ctrl.PasswordResetConfirm)
		tutorAuth.GET("/profile", ctrl.GetProfile)
	}
}
