package response

// GenericResponse is a standard API response
type GenericResponse struct {
	Message string `json:"message"`
}

// ErrorResponse is a standard error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// LoginResponse for successful login
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// SessionsResponse for listing sessions
type SessionsResponse struct {
	Sessions []string `json:"sessions"`
}

// StatusResponse for status endpoint
type StatusResponse struct {
	Status string `json:"status"`
}

// ProfileResponse for tutor profile endpoint
// Excludes sensitive fields like Password
type ProfileResponse struct {
	ID        uint   `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	Status    string `json:"status"`
}

// LoginWithProfileResponse for successful login with profile
type LoginWithProfileResponse struct {
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
	Profile      ProfileResponse `json:"profile"`
}
