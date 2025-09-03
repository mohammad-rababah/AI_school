package response

type FacilityOwnerProfileResponse struct {
	ID     uint   `json:"id"`
	Email  string `json:"email"`
	Phone  string `json:"phone"`
	Role   string `json:"role"`
	Status string `json:"status"`
}

type FacilityOwnerLoginWithProfileResponse struct {
	AccessToken  string                       `json:"access_token"`
	RefreshToken string                       `json:"refresh_token"`
	Profile      FacilityOwnerProfileResponse `json:"profile"`
}
