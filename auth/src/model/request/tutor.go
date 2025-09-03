package request

// VerifyRequest for /verify endpoint
// Accepts either email or phone
// Service will determine type
type VerifyRequest struct {
	EmailOrPhone string `json:"email_or_phone" binding:"required"`
	OTP          string `json:"otp" binding:"required"`
}

// RegisterRequest for /register endpoint
type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Phone     string `json:"phone" binding:"required"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
}

// LoginRequest for /login endpoint
type LoginRequest struct {
	EmailOrPhone string `json:"email_or_phone" binding:"required"`
	Password     string `json:"password" binding:"required"`
}

// TokenRefreshRequest for /token/refresh endpoint
type TokenRefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// PasswordResetRequest for /password/reset/request endpoint
type PasswordResetRequest struct {
	EmailOrPhone string `json:"email_or_phone" binding:"required"`
}

// PasswordResetConfirmRequest for /password/reset/confirm endpoint
type PasswordResetConfirmRequest struct {
	EmailOrPhone string `json:"email_or_phone" binding:"required"`
	OTP          string `json:"otp" binding:"required"`
	NewPassword  string `json:"new_password" binding:"required,min=8"`
}

// DeleteSessionRequest for /sessions/:id endpoint
type DeleteSessionRequest struct {
	SessionID string `uri:"id" binding:"required"`
}
