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
