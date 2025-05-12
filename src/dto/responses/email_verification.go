package responses

import "github.com/golang-jwt/jwt/v5"

// EmailVerification struct for email verification response.
type EmailVerification struct {
	UserID    uint   `json:"userId"`
	UserEmail string `json:"userEmail"`
	Email     Token  `json:"email"`
}

// SetEmailVerification sets the token and its expiry time.
func (ev *EmailVerification) SetEmailVerification(userID uint, userEmail, token string, expiresAt *jwt.NumericDate) {
	ev.UserID = userID
	ev.UserEmail = userEmail
	ev.Email.Token = token
	ev.Email.ExpiresAt = expiresAt.Time
}
