package requests

// UsernamePasswordSignIn struct for username password sign-in request.
type UsernamePasswordSignIn struct {
	App      string `json:"app" validate:"required"`
	DeviceID string `json:"deviceId" validate:"required"`
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}
