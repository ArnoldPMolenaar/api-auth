package requests

type UpdateUserSignedIn struct {
	Username    string  `json:"username" validate:"required"`
	Email       string  `json:"email" validate:"required,email"`
	PhoneNumber *string `json:"phoneNumber"`
}
