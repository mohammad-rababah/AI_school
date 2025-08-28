package common

// GenericResponse is a standard API response
type GenericResponse struct {
	Message string `json:"message"`
}

// ErrorResponse is a standard error response
type ErrorResponse struct {
	Error string `json:"error"`
}
