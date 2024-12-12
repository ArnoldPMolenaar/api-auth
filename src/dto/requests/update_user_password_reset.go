package requests

// UpdateUserPasswordReset struct is used to update the user password from a reset endpoint.
type UpdateUserPasswordReset struct {
	App      string `json:"app" validate:"required"`
	Password string `json:"password" validate:"required"`
}
