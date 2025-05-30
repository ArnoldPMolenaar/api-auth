package claims

import (
	"api-auth/main/src/enums"
	"github.com/golang-jwt/jwt/v5"
)

// AccessClaims struct to hold the access token claims.
type AccessClaims struct {
	IdentityClaims
	IsEmailVerified bool                           `json:"isEmailVerified"`
	IsPhoneVerified bool                           `json:"isPhoneVerified"`
	IsTempPassword  bool                           `json:"isTempPassword"`
	Apps            map[string]map[string][]string `json:"apps"`
	Type            enums.TokenType                `json:"type"`
	jwt.RegisteredClaims
}
