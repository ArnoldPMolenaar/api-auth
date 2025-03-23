package responses

import (
	"time"
)

// Token struct that represents a token in the json response.
type Token struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// SetToken sets the token and its expiry time.
func (t *Token) SetToken(token string, expiresAt time.Time) {
	t.Token = token
	t.ExpiresAt = expiresAt
}
