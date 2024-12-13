package claims

import (
	"api-auth/main/src/enums"
	"github.com/golang-jwt/jwt/v5"
)

// EmailVerificationClaims struct to hold the verification token claims.
type EmailVerificationClaims struct {
	IdentityClaims
	Type  enums.TokenType `json:"type"`
	Email string          `json:"email"`
	jwt.RegisteredClaims
}
