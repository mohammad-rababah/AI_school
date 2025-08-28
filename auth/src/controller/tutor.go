package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/mohammad-rababah/AI_school/auth/src/model/request"
	"github.com/mohammad-rababah/AI_school/auth/src/model/response"
	"github.com/mohammad-rababah/AI_school/auth/src/service"
	"github.com/mohammad-rababah/AI_school/common"
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

func (t *tutorController) Init(c *gin.Context) {
	var req request.InitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, common.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.Init(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, common.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, common.GenericResponse{Message: "tutor init"})
}

func (t *tutorController) VerifyEmail(c *gin.Context) {
	var req request.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, common.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.VerifyEmail(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, common.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, common.GenericResponse{Message: "verify email"})
}

func (t *tutorController) VerifyPhone(c *gin.Context) {
	var req request.VerifyPhoneRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, common.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.VerifyPhone(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, common.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, common.GenericResponse{Message: "verify phone"})
}

func (t *tutorController) Register(c *gin.Context) {
	var req request.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, common.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.Register(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, common.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, common.GenericResponse{Message: "register"})
}

func (t *tutorController) Login(c *gin.Context) {
	var req request.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, common.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.Login(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusUnauthorized, common.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.LoginResponse{AccessToken: "", RefreshToken: ""}) // stub
}

func (t *tutorController) TokenRefresh(c *gin.Context) {
	var req request.TokenRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, common.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.TokenRefresh(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusUnauthorized, common.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.LoginResponse{AccessToken: "", RefreshToken: ""}) // stub
}

func (t *tutorController) Logout(c *gin.Context) {
	userID := c.GetString("userID") // placeholder, should be extracted from context/session
	if err := t.service.Logout(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, common.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, common.GenericResponse{Message: "logout"})
}

func (t *tutorController) GetSessions(c *gin.Context) {
	userID := c.GetString("userID") // placeholder
	sessions, err := t.service.GetSessions(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, common.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response.SessionsResponse{Sessions: sessions})
}

func (t *tutorController) DeleteSession(c *gin.Context) {
	var req request.DeleteSessionRequest
	if err := c.ShouldBindUri(&req); err != nil {
		c.JSON(http.StatusBadRequest, common.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.DeleteSession(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, common.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, common.GenericResponse{Message: "delete session"})
}

func (t *tutorController) PasswordResetRequest(c *gin.Context) {
	var req request.PasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, common.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.PasswordResetRequest(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, common.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, common.GenericResponse{Message: "password reset request"})
}

func (t *tutorController) PasswordResetConfirm(c *gin.Context) {
	var req request.PasswordResetConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, common.ErrorResponse{Error: err.Error()})
		return
	}
	if err := t.service.PasswordResetConfirm(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, common.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, common.GenericResponse{Message: "password reset confirm"})
}

func (t *tutorController) GetStatus(c *gin.Context) {
	userID := c.GetString("userID") // placeholder
	status, err := t.service.GetStatus(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, common.ErrorResponse{Error: err.Error()})
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
	tutor := rg.Group("tutor/auth")
	{
		tutor.POST("/init", ctrl.Init)
		tutor.POST("/verify/email", ctrl.VerifyEmail)
		tutor.POST("/verify/phone", ctrl.VerifyPhone)
		tutor.POST("/register", ctrl.Register)
		tutor.POST("/login", ctrl.Login)
		tutor.POST("/token/refresh", ctrl.TokenRefresh)
		tutor.POST("/logout", ctrl.Logout)
		tutor.GET("/sessions", ctrl.GetSessions)
		tutor.DELETE("/sessions/:id", ctrl.DeleteSession)
		tutor.POST("/password/reset/request", ctrl.PasswordResetRequest)
		tutor.POST("/password/reset/confirm", ctrl.PasswordResetConfirm)
		tutor.GET("/status", ctrl.GetStatus)
	}
}
