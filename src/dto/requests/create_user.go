package requests

import "api-auth/main/src/dto/responses"

// CreateUser struct for creating a user request.
type CreateUser struct {
	Username    string                `json:"username" validate:"required"`
	Email       string                `json:"email" validate:"required,email"`
	PhoneNumber *string               `json:"phoneNumber"`
	Password    string                `json:"password"`
	Roles       []responses.AppRole   `json:"roles" validate:"dive"`
	Recipes     []responses.AppRecipe `json:"recipes" validate:"dive"`
}
