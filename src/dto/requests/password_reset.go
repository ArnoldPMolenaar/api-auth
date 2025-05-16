package requests

// PasswordReset struct for password reset request.
type PasswordReset struct {
	App      string `json:"app" validate:"required"`
	DeviceID string `json:"deviceId" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
}
