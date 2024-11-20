package services

import (
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

type TokenType string

type TokenClaims struct {
	Id        int       `json:"id"`
	TokenType TokenType `json:"tokenType"`
	jwt.RegisteredClaims
}

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
func TokenCreate(id int, expireTime int, duration time.Duration, tokenType TokenType) (string, error) {
	iat := jwt.NewNumericDate(time.Now())
	exp := jwt.NewNumericDate(time.Now().Add(time.Duration(expireTime) * duration))

	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), &TokenClaims{
		Id:        id,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  iat,
			ExpiresAt: exp,
		},
	})

	tokenString, err := token.SignedString([]byte(TokenSecretKey))

	return tokenString, err
}

// TokenParse parses token, validates it and returns the claims from the token or an error.
func TokenParse(tokenString string, claims jwt.Claims) error {
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(TokenSecretKey), nil
	})

	if err != nil || !token.Valid {
		return err
	}

	return nil
}
