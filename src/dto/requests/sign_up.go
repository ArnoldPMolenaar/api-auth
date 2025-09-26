package requests

import "api-auth/main/src/dto/responses"

// SignUp struct for username password signup request.
type SignUp struct {
	AppName     string                `json:"appName" validate:"required"`
	Username    string                `json:"username" validate:"required"`
	Email       string                `json:"email" validate:"required,email"`
	PhoneNumber *string               `json:"phoneNumber"`
	Password    string                `json:"password"`
	Recipes     []responses.AppRecipe `json:"recipes" validate:"dive"`
}
