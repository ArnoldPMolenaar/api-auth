package services

import (
	"api-auth/main/src/claims"
	"api-auth/main/src/enums"
	"api-auth/main/src/models"
	"api-auth/main/src/utils"
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2/log"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"strconv"
	"time"
)

var TokenRefreshExpireHours int
var TokenAccessExpireMinutes int
var TokenPasswordResetExpireMinutes int
var TokenEmailVerificationExpireHours int
var TokenSecretKey string

// Initialise the environment variables needed to create tokens.
// If initialisation fails => crash the application.
func init() {
	tokenRefreshExpireHours, err := strconv.Atoi(os.Getenv("TOKEN_REFRESH_EXPIRE_HOURS"))
	if err != nil {
		log.Error("Refresh token expire hours is not a number.")
	}

	tokenAccessExpireMinutes, err := strconv.Atoi(os.Getenv("TOKEN_ACCESS_EXPIRE_MINUTES"))
	if err != nil {
		log.Error("Access token expire minutes is not a number.")
	}

	tokenPasswordResetExpireMinutes, err := strconv.Atoi(os.Getenv("TOKEN_PASSWORD_RESET_EXPIRE_MINUTES"))
	if err != nil {
		log.Error("Password reset token expire minutes is not a number.")
	}

	tokenEmailVerificationExpireHours, err := strconv.Atoi(os.Getenv("TOKEN_EMAIL_VERIFICATION_EXPIRE_HOURS"))
	if err != nil {
		log.Error("Email verification token expire hours is not a number.")
	}

	TokenRefreshExpireHours = tokenRefreshExpireHours
	TokenAccessExpireMinutes = tokenAccessExpireMinutes
	TokenPasswordResetExpireMinutes = tokenPasswordResetExpireMinutes
	TokenEmailVerificationExpireHours = tokenEmailVerificationExpireHours
	TokenSecretKey = os.Getenv("TOKEN_SECRET_KEY")
}

// TokenCreate creates a new token with the given id, expire time, duration and token type.
func TokenCreate(claim interface{}, expireTime int, duration time.Duration, tokenType enums.TokenType) (string, *jwt.NumericDate, error) {
	iat := jwt.NewNumericDate(time.Now().UTC())
	exp := jwt.NewNumericDate(time.Now().UTC().Add(time.Duration(expireTime) * duration))

	var token *jwt.Token

	switch tokenType {
	case enums.Access:
		accessClaims, ok := claim.(claims.AccessClaims)
		if !ok {
			return "", nil, errors.New("invalid claim type for access token")
		}

		accessClaims.RegisteredClaims = jwt.RegisteredClaims{
			IssuedAt:  iat,
			ExpiresAt: exp,
		}
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	default:
		return "", nil, errors.New("unsupported token type")
	}

	tokenString, err := token.SignedString([]byte(TokenSecretKey))

	return tokenString, exp, err
}

// TokenParse parses token, validates it and returns the claims from the token or an error.
func TokenParse(tokenString string, tokenType enums.TokenType) (interface{}, error) {
	var claim jwt.Claims

	switch tokenType {
	case enums.Access:
		claim = &claims.AccessClaims{}
	default:
		return nil, errors.New("unsupported token type")
	}

	token, err := jwt.ParseWithClaims(tokenString, claim, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(TokenSecretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	switch payload := token.Claims.(type) {
	case *claims.AccessClaims:
		return payload, nil
	default:
		return nil, errors.New("unknown claims type")
	}
}

// TokenRefreshValidUntil returns the time when the refresh token will expire.
func TokenRefreshValidUntil() time.Time {
	return time.Now().UTC().Add(time.Duration(TokenRefreshExpireHours) * time.Hour)
}

// TokenCreateAccessClaim creates a new access claim from the given user.
func TokenCreateAccessClaim(user models.User) claims.AccessClaims {
	claim := claims.AccessClaims{
		Id:              int(user.ID),
		IsEmailVerified: user.EmailVerifiedAt.Valid,
		IsPhoneVerified: user.PhoneVerifiedAt.Valid,
		IsTempPassword:  user.IsTempPassword,
		Roles:           make(map[string][]string),
		Type:            enums.Access,
	}

	for _, role := range user.AppRoles {
		var roleName = utils.PascalCaseToCamelcase(role.RoleName)
		claim.Roles[roleName] = []string{}
		for _, permission := range role.Role.Permissions {
			claim.Roles[roleName] = append(claim.Roles[roleName], permission.Name)
		}
	}

	return claim
}
