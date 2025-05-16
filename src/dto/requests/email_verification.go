package requests

type EmailVerification struct {
	DeviceID string `json:"deviceId" validate:"required"`
}
