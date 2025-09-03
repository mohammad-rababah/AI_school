package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/mohammad-rababah/AI_school/auth/src/middleware"
	"github.com/mohammad-rababah/AI_school/auth/src/model/request"
	"github.com/mohammad-rababah/AI_school/auth/src/model/response"
	"github.com/mohammad-rababah/AI_school/auth/src/service"
	"net/http"
)

type FacilityOwnerController interface {
	Register(c *gin.Context)
	VerifyEmail(c *gin.Context)
	VerifyPhone(c *gin.Context)
	Login(c *gin.Context)
	Logout(c *gin.Context)
	GetSessions(c *gin.Context)
	DeleteSession(c *gin.Context)
	PasswordResetRequest(c *gin.Context)
	PasswordResetConfirm(c *gin.Context)
	GetProfile(c *gin.Context)
	TokenRefresh(c *gin.Context)
	OnboardingDocuments(c *gin.Context)
	GetStatus(c *gin.Context)
}

type facilityOwnerController struct {
	service service.FacilityOwnerService
}

// Register godoc
// @Summary      Register facility owner
// @Description  Registers a new facility owner
// @Tags         facility_owner
// @Accept       json
// @Produce      json
// @Param        request body request.FacilityOwnerRegisterRequest true "Register request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /facility/auth/register [post]
func (f *facilityOwnerController) Register(c *gin.Context) {
	var req request.FacilityOwnerRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := f.service.Register(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "facility owner registered"})
}

// VerifyEmail godoc
// @Summary      Verify facility owner email
// @Description  Verifies the email with OTP
// @Tags         facility_owner
// @Accept       json
// @Produce      json
// @Param        request body request.FacilityOwnerVerifyEmailRequest true "Verify email request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /facility/auth/verify/email [post]
func (f *facilityOwnerController) VerifyEmail(c *gin.Context) {
	var req request.FacilityOwnerVerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := f.service.VerifyEmail(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "verify email"})
}

// VerifyPhone godoc
// @Summary      Verify facility owner phone
// @Description  Verifies the phone with OTP
// @Tags         facility_owner
// @Accept       json
// @Produce      json
// @Param        request body request.FacilityOwnerVerifyPhoneRequest true "Verify phone request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /facility/auth/verify/phone [post]
func (f *facilityOwnerController) VerifyPhone(c *gin.Context) {
	var req request.FacilityOwnerVerifyPhoneRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := f.service.VerifyPhone(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "verify phone"})
}

// Login godoc
// @Summary      Facility owner login
// @Description  Authenticates facility owner and returns JWT tokens and profile
// @Tags         facility_owner
// @Accept       json
// @Produce      json
// @Param        request body request.FacilityOwnerLoginRequest true "Login request"
// @Success      200 {object} response.FacilityOwnerLoginWithProfileResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /facility/auth/login [post]
func (f *facilityOwnerController) Login(c *gin.Context) {
	var req request.FacilityOwnerLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	accessToken, refreshToken, owner, err := f.service.Login(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{Error: err.Error()})
		return
	}
	resp := response.FacilityOwnerLoginWithProfileResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Profile: response.FacilityOwnerProfileResponse{
			ID:     owner.ID,
			Email:  owner.Email,
			Phone:  owner.Phone,
			Role:   owner.Role,
			Status: string(owner.Status),
		},
	}
	c.JSON(http.StatusOK, resp)
}

// Logout godoc
// @Summary      Facility owner logout
// @Description  Logs out the facility owner and invalidates session
// @Tags         facility_owner
// @Produce      json
// @Success      200 {object} response.GenericResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /facility/auth/logout [post]
func (f *facilityOwnerController) Logout(c *gin.Context) {
	userID := c.GetString("userID")
	if err := f.service.Logout(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "logout"})
}

// GetSessions godoc
// @Summary      Get active sessions
// @Description  Returns all active sessions for the facility owner
// @Tags         facility_owner
// @Produce      json
// @Success      200 {object} response.SessionsResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /facility/auth/sessions [get]
func (f *facilityOwnerController) GetSessions(c *gin.Context) {
	userID := c.GetString("userID")
	sessions, err := f.service.GetSessions(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.SessionsResponse{Sessions: sessions})
}

// DeleteSession godoc
// @Summary      Delete session
// @Description  Deletes a specific session by ID
// @Tags         facility_owner
// @Produce      json
// @Param        id path string true "Session ID"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /facility/auth/sessions/{id} [delete]
func (f *facilityOwnerController) DeleteSession(c *gin.Context) {
	var req request.FacilityOwnerDeleteSessionRequest
	if err := c.ShouldBindUri(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := f.service.DeleteSession(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "delete session"})
}

// PasswordResetRequest godoc
// @Summary      Request password reset
// @Description  Requests a password reset for facility owner
// @Tags         facility_owner
// @Accept       json
// @Produce      json
// @Param        request body request.FacilityOwnerPasswordResetRequest true "Password reset request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /facility/auth/password/reset/request [post]
func (f *facilityOwnerController) PasswordResetRequest(c *gin.Context) {
	var req request.FacilityOwnerPasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := f.service.PasswordResetRequest(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "password reset request"})
}

// PasswordResetConfirm godoc
// @Summary      Confirm password reset
// @Description  Confirms password reset with OTP and new password
// @Tags         facility_owner
// @Accept       json
// @Produce      json
// @Param        request body request.FacilityOwnerPasswordResetConfirmRequest true "Password reset confirm request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /facility/auth/password/reset/confirm [post]
func (f *facilityOwnerController) PasswordResetConfirm(c *gin.Context) {
	var req request.FacilityOwnerPasswordResetConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := f.service.PasswordResetConfirm(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "password reset confirm"})
}

// GetProfile godoc
// @Summary      Get facility owner profile
// @Description  Returns the current profile of the facility owner
// @Tags         facility_owner
// @Produce      json
// @Success      200 {object} response.FacilityOwnerProfileResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /facility/auth/profile [get]
func (f *facilityOwnerController) GetProfile(c *gin.Context) {
	userID := c.GetString("userID")
	owner, err := f.service.GetProfile(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	resp := response.FacilityOwnerProfileResponse{
		ID:     owner.ID,
		Email:  owner.Email,
		Phone:  owner.Phone,
		Role:   owner.Role,
		Status: string(owner.Status),
	}
	c.JSON(http.StatusOK, resp)
}

// TokenRefresh godoc
// @Summary      Refresh facility owner tokens
// @Description  Refreshes the access and refresh tokens for the facility owner
// @Tags         facility_owner
// @Accept       json
// @Produce      json
// @Param        request body request.FacilityOwnerTokenRefreshRequest true "Token refresh request"
// @Success      200 {object} response.LoginResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /facility/auth/token/refresh [post]
func (f *facilityOwnerController) TokenRefresh(c *gin.Context) {
	var req request.FacilityOwnerTokenRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "Missing or invalid refresh token"})
		return
	}
	accessToken, refreshToken, err := f.service.RefreshTokens(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// OnboardingDocuments godoc
// @Summary      Submit onboarding documents
// @Description  Submits onboarding documents for a facility
// @Tags         facility_owner
// @Accept       json
// @Produce      json
// @Param        request body request.FacilityOwnerOnboardingDocumentsRequest true "Onboarding documents request"
// @Success      200 {object} response.GenericResponse
// @Failure      400 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /facility/auth/onboarding/documents [post]
func (f *facilityOwnerController) OnboardingDocuments(c *gin.Context) {
	var req request.FacilityOwnerOnboardingDocumentsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: err.Error()})
		return
	}
	if err := f.service.OnboardingDocuments(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.GenericResponse{Message: "onboarding documents submitted"})
}

// GetStatus godoc
// @Summary      Get facility owner status
// @Description  Returns the current status of the facility owner
// @Tags         facility_owner
// @Produce      json
// @Success      200 {object} response.StatusResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /facility/auth/status [get]
func (f *facilityOwnerController) GetStatus(c *gin.Context) {
	userID := c.GetString("userID")
	status, err := f.service.GetStatus(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.StatusResponse{Status: status})
}

func NewFacilityOwnerController(s service.FacilityOwnerService) FacilityOwnerController {
	return &facilityOwnerController{service: s}
}

func InitFacilityOwnerAPIs(rg *gin.RouterGroup, s service.FacilityOwnerService) {
	ctrl := NewFacilityOwnerController(s)
	facility := rg.Group("facility/auth")
	{
		facility.POST("/register", ctrl.Register)
		facility.POST("/verify/email", ctrl.VerifyEmail)
		facility.POST("/verify/phone", ctrl.VerifyPhone)
		facility.POST("/login", ctrl.Login)
		facility.POST("/password/reset/request", ctrl.PasswordResetRequest)
		facility.POST("/token/refresh", ctrl.TokenRefresh)
		facility.POST("/onboarding/documents", ctrl.OnboardingDocuments)
	}
	facilityAuth := facility.Group("").Use(middleware.JWTAuthMiddleware())
	{
		facilityAuth.POST("/logout", ctrl.Logout)
		facilityAuth.GET("/sessions", ctrl.GetSessions)
		facilityAuth.DELETE("/sessions/:id", ctrl.DeleteSession)
		facilityAuth.POST("/password/reset/confirm", ctrl.PasswordResetConfirm)
		facilityAuth.GET("/profile", ctrl.GetProfile)
		facilityAuth.GET("/status", ctrl.GetStatus)
	}
}
