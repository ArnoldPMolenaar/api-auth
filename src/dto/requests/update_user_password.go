package requests

// UpdateUserPassword struct is used to update the user password.
type UpdateUserPassword struct {
	OldPassword string `json:"oldPassword" validate:"required"`
	NewPassword string `json:"newPassword" validate:"required"`
}
