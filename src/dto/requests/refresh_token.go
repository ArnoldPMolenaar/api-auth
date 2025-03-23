package requests

// RefreshToken struct to hold refresh token request data.
type RefreshToken struct {
	UserID       uint   `json:"userId" validate:"required"`
	DeviceID     string `json:"deviceId" validate:"required"`
	App          string `json:"app" validate:"required"`
	RefreshToken string `json:"refreshToken" validate:"required"`
}
