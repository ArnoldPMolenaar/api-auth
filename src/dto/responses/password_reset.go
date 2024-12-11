package responses

import "github.com/golang-jwt/jwt/v5"

// PasswordReset struct for password reset response.
type PasswordReset struct {
	ID    uint  `json:"id"`
	Reset Token `json:"reset"`
}

// SetPasswordReset sets the token and its expiry time.
func (pr *PasswordReset) SetPasswordReset(userID uint, token string, expiresAt *jwt.NumericDate) {
	pr.ID = userID
	pr.Reset.Token = token
	pr.Reset.ExpiresAt = expiresAt.Time
}
