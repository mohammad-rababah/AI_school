package errors

// AppError is a general error struct containing both business and technical messages
// BusinessMsg: message intended for frontend display
// TechMsg: message intended for internal logging/debugging
type AppError struct {
	BusinessMsg string
	TechMsg     string
}

func (e *AppError) Error() string {
	return e.BusinessMsg
}

func NewAppError(businessMsg, techMsg string) error {
	return &AppError{
		BusinessMsg: businessMsg,
		TechMsg:     techMsg,
	}
}
