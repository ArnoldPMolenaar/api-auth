package requests

import "api-auth/main/src/dto/responses"

// SignUp struct for username password signup request.
type SignUp struct {
	Username    string                `json:"username" validate:"required"`
	Email       string                `json:"email" validate:"required,email"`
	PhoneNumber *string               `json:"phoneNumber"`
	Password    string                `json:"password"`
	Roles       []responses.AppRole   `json:"roles"`
	Recipes     []responses.AppRecipe `json:"recipes"`
}
