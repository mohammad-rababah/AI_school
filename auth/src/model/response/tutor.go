package response

// All tutor response types are now in common.go
// This file is intentionally left empty.

type TutorProfileResponse struct {
	ID        uint   `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	Status    string `json:"status"`
}

type TutorLoginWithProfileResponse struct {
	AccessToken  string               `json:"access_token"`
	RefreshToken string               `json:"refresh_token"`
	Profile      TutorProfileResponse `json:"profile"`
}
