package requests

import (
	"api-auth/main/src/dto/responses"
	"time"
)

type UpdateUser struct {
	Username    string                `json:"username" validate:"required"`
	Email       string                `json:"email" validate:"required,email"`
	PhoneNumber *string               `json:"phoneNumber"`
	UpdatedAt   time.Time             `json:"updatedAt" validate:"required"`
	Roles       []responses.AppRole   `json:"roles"`
	Recipes     []responses.AppRecipe `json:"recipes"`
}
