package claims

import (
	"github.com/golang-jwt/jwt/v5"
)

// PasswordResetClaims struct to hold the password reset token claims.
type PasswordResetClaims struct {
	IdentityClaims
	jwt.RegisteredClaims
}
