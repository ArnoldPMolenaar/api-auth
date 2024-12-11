package services

import (
	"api-auth/main/src/cache"
	"api-auth/main/src/claims"
	"api-auth/main/src/enums"
	"api-auth/main/src/models"
	"api-auth/main/src/utils"
	"context"
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
func TokenCreate(payload interface{}, expireTime int, duration time.Duration, tokenType enums.TokenType) (string, *jwt.NumericDate, error) {
	iat := jwt.NewNumericDate(time.Now().UTC())
	exp := jwt.NewNumericDate(time.Now().UTC().Add(time.Duration(expireTime) * duration))

	var claim jwt.Claims

	switch tokenType {
	case enums.Access:
		accessClaims, ok := payload.(claims.AccessClaims)
		if !ok {
			return "", nil, errors.New("invalid claim type for access token")
		}
		accessClaims.RegisteredClaims.IssuedAt = iat
		accessClaims.RegisteredClaims.ExpiresAt = exp
		claim = &accessClaims
	case enums.PasswordReset:
		passwordResetClaims, ok := payload.(claims.PasswordResetClaims)
		if !ok {
			return "", nil, errors.New("invalid claim type for password reset token")
		}
		passwordResetClaims.RegisteredClaims.IssuedAt = iat
		passwordResetClaims.RegisteredClaims.ExpiresAt = exp
		claim = &passwordResetClaims
	default:
		return "", nil, errors.New("unsupported token type")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	tokenString, err := token.SignedString([]byte(TokenSecretKey))

	return tokenString, exp, err
}

// TokenParse parses token, validates it and returns the claims from the token or an error.
func TokenParse(accessToken string, tokenType enums.TokenType) (interface{}, error) {
	var claim jwt.Claims

	switch tokenType {
	case enums.Access:
		claim = &claims.AccessClaims{}
	case enums.PasswordReset:
		claim = &claims.PasswordResetClaims{}
	default:
		return nil, errors.New("unsupported token type")
	}

	token, err := jwt.ParseWithClaims(accessToken, claim, func(token *jwt.Token) (interface{}, error) {
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
	case *claims.PasswordResetClaims:
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
func TokenCreateAccessClaim(user *models.User, app string) claims.AccessClaims {
	claim := claims.AccessClaims{
		IdentityClaims: claims.IdentityClaims{
			Id:  int(user.ID),
			App: app,
		},
		IsEmailVerified: user.EmailVerifiedAt.Valid,
		IsPhoneVerified: user.PhoneVerifiedAt.Valid,
		IsTempPassword:  user.IsTempPassword,
		Roles:           make(map[string][]string),
		Type:            enums.Access,
	}

	for i := range user.AppRoles {
		var roleName = utils.PascalCaseToCamelcase(user.AppRoles[i].RoleName)
		claim.Roles[roleName] = []string{}
		for j := range user.AppRoles[i].Role.Permissions {
			claim.Roles[roleName] = append(claim.Roles[roleName], user.AppRoles[i].Role.Permissions[j].Name)
		}
	}

	return claim
}

// TokenCreatePasswordResetClaim creates a new password reset claim from the given user.
func TokenCreatePasswordResetClaim(userID uint, app string) claims.PasswordResetClaims {
	return claims.PasswordResetClaims{
		IdentityClaims: claims.IdentityClaims{
			Id:  int(userID),
			App: app,
		},
		Type: enums.PasswordReset,
	}
}

// TokenFromCache returns the token from the cache.
func TokenFromCache(app string, userID uint, tokenType enums.TokenType) (string, error) {
	key := cacheKey(app, userID, tokenType)

	if result := cache.Valkey.Do(context.Background(), cache.Valkey.B().Get().Key(key).Build()); result.Error() != nil {
		return "", result.Error()
	} else {
		if value, err := result.ToString(); err != nil {
			return "", err
		} else {
			return value, nil
		}
	}
}

// TokenToCache saves the token to the cache.
func TokenToCache(app string, userID uint, token string, exp time.Time, tokenType enums.TokenType) error {
	key := cacheKey(app, userID, tokenType)

	if result := cache.Valkey.Do(context.Background(), cache.Valkey.B().Set().Key(key).Value(token).Exat(exp).Build()); result.Error() != nil {
		return result.Error()
	} else {
		return nil
	}
}

// TokenDeleteFromCache deletes the token from the cache.
func TokenDeleteFromCache(app string, userID uint, tokenType enums.TokenType) error {
	key := cacheKey(app, userID, tokenType)

	if result := cache.Valkey.Do(context.Background(), cache.Valkey.B().Del().Key(key).Build()); result.Error() != nil {
		return result.Error()
	} else {
		return nil
	}
}

// TokenExistsInCache checks if the token exists in the cache.
func TokenExistsInCache(app string, userID uint, tokenType enums.TokenType) (bool, error) {
	key := cacheKey(app, userID, tokenType)

	if result := cache.Valkey.Do(context.Background(), cache.Valkey.B().Exists().Key(key).Build()); result.Error() != nil {
		return false, result.Error()
	} else {
		if value, err := result.ToInt64(); err != nil {
			return false, err
		} else {
			return value == 1, nil
		}
	}
}

// cacheKey returns the key for the token cache.
func cacheKey(app string, userID uint, tokenType enums.TokenType) string {
	var key string

	switch tokenType {
	case enums.Access:
		key = tokenCacheKey(app, userID)
	case enums.PasswordReset:
		key = tokenPasswordResetCacheKey(app, userID)
	}

	return key
}

// tokenCacheKey returns the key for the token cache.
func tokenCacheKey(app string, userID uint) string {
	return fmt.Sprintf("%s:%d:AccessToken", app, userID)
}

// tokenPasswordResetCacheKey returns the key for password reset token cache.
func tokenPasswordResetCacheKey(app string, userID uint) string {
	return fmt.Sprintf("%s:%d:PasswordResetToken", app, userID)
}
