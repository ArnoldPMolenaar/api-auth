package claims

import (
	"api-auth/main/src/enums"
	"github.com/golang-jwt/jwt/v5"
)

// AccessClaims struct to hold the access token claims.
type AccessClaims struct {
	Id              int                 `json:"id"`
	IsEmailVerified bool                `json:"isEmailVerified"`
	IsPhoneVerified bool                `json:"isPhoneVerified"`
	IsTempPassword  bool                `json:"isTempPassword"`
	Roles           map[string][]string `json:"roles"`
	Type            enums.TokenType     `json:"type"`
	jwt.RegisteredClaims
}
