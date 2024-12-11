package claims

import (
	"api-auth/main/src/enums"
	"github.com/golang-jwt/jwt/v5"
)

// PasswordResetClaims struct to hold the password reset token claims.
type PasswordResetClaims struct {
	IdentityClaims
	Type enums.TokenType `json:"type"`
	jwt.RegisteredClaims
}
