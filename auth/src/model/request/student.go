package request

// RegisterRequest for /register endpoint
// Students register with email OR phone

type StudentRegisterRequest struct {
	Email     string `json:"email" binding:"omitempty,email"`
	Phone     string `json:"phone" binding:"omitempty"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
}

// VerifyRequest for /verify endpoint
// Accepts either email or phone
// Service will determine type
type StudentVerifyRequest struct {
	EmailOrPhone string `json:"email_or_phone" binding:"required"`
	OTP          string `json:"otp" binding:"required"`
}

// LoginRequest for /login endpoint
type StudentLoginRequest struct {
	EmailOrPhone string `json:"email_or_phone" binding:"required"`
	Password     string `json:"password" binding:"required"`
}

// TokenRefreshRequest for /token/refresh endpoint
type StudentTokenRefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// PasswordResetRequest for /password/reset/request endpoint
type StudentPasswordResetRequest struct {
	EmailOrPhone string `json:"email_or_phone" binding:"required"`
}

// PasswordResetConfirmRequest for /password/reset/confirm endpoint
type StudentPasswordResetConfirmRequest struct {
	EmailOrPhone string `json:"email_or_phone" binding:"required"`
	OTP          string `json:"otp" binding:"required"`
	NewPassword  string `json:"new_password" binding:"required,min=8"`
}

// DeleteSessionRequest for /sessions/:id endpoint
type StudentDeleteSessionRequest struct {
	SessionID string `uri:"id" binding:"required"`
}
