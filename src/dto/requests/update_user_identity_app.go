package requests

// UpdateUserIdentityApp struct to hold the app name for updating user identity.
type UpdateUserIdentityApp struct {
	App string `json:"app" validate:"required"`
}
