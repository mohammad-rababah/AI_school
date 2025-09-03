package request

// RegisterRequest for /register endpoint
// Facility owners register with email and phone

type FacilityOwnerRegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Phone    string `json:"phone" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

type FacilityOwnerVerifyEmailRequest struct {
	Email string `json:"email" binding:"required,email"`
	OTP   string `json:"otp" binding:"required"`
}

type FacilityOwnerVerifyPhoneRequest struct {
	Phone string `json:"phone" binding:"required"`
	OTP   string `json:"otp" binding:"required"`
}

type FacilityOwnerLoginRequest struct {
	EmailOrPhone string `json:"email_or_phone" binding:"required"`
	Password     string `json:"password" binding:"required"`
}

type FacilityOwnerTokenRefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type FacilityOwnerPasswordResetRequest struct {
	EmailOrPhone string `json:"email_or_phone" binding:"required"`
}

type FacilityOwnerPasswordResetConfirmRequest struct {
	EmailOrPhone string `json:"email_or_phone" binding:"required"`
	OTP          string `json:"otp" binding:"required"`
	NewPassword  string `json:"new_password" binding:"required,min=8"`
}

type FacilityOwnerDeleteSessionRequest struct {
	SessionID string `uri:"id" binding:"required"`
}

type FacilityOwnerOnboardingDocumentsRequest struct {
	FacilityID uint   `json:"facility_id" binding:"required"`
	Documents  string `json:"documents" binding:"required"` // JSON string for docs
}
