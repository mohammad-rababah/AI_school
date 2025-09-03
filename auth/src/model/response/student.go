package response

// StudentProfileResponse for student profile endpoint
type StudentProfileResponse struct {
	ID        uint   `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	Status    string `json:"status"`
}

// StudentLoginWithProfileResponse for successful login with profile
type StudentLoginWithProfileResponse struct {
	AccessToken  string                 `json:"access_token"`
	RefreshToken string                 `json:"refresh_token"`
	Profile      StudentProfileResponse `json:"profile"`
}
