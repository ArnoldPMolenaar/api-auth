package requests

type SignOut struct {
	DeviceID string `json:"deviceId" validate:"required"`
}
