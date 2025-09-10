package services

import (
	"api-auth/main/src/cache"
	"api-auth/main/src/claims"
	"api-auth/main/src/enums"
	"api-auth/main/src/models"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/ArnoldPMolenaar/api-utils/utils"
	"github.com/gofiber/fiber/v2/log"
	"github.com/golang-jwt/jwt/v5"
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
	case enums.EmailVerification:
		emailClaims, ok := payload.(claims.EmailVerificationClaims)
		if !ok {
			return "", nil, errors.New("invalid claim type for email verification token")
		}
		emailClaims.RegisteredClaims.IssuedAt = iat
		emailClaims.RegisteredClaims.ExpiresAt = exp
		claim = &emailClaims
	default:
		return "", nil, errors.New("unsupported token type")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	tokenString, err := token.SignedString([]byte(TokenSecretKey))

	return tokenString, exp, err
}

// TokenUpdate updates an existing token with the given payload and token type.
// It keeps the original issued at and expiration time.
func TokenUpdate(payload interface{}, tokenType enums.TokenType) (string, error) {
	var claim jwt.Claims

	switch tokenType {
	case enums.Access:
		accessClaims, ok := payload.(*claims.AccessClaims)
		if !ok {
			return "", errors.New("invalid claim type for access token")
		}
		claim = accessClaims
	case enums.PasswordReset:
		passwordResetClaims, ok := payload.(*claims.PasswordResetClaims)
		if !ok {
			return "", errors.New("invalid claim type for password reset token")
		}
		claim = passwordResetClaims
	case enums.EmailVerification:
		emailClaims, ok := payload.(*claims.EmailVerificationClaims)
		if !ok {
			return "", errors.New("invalid claim type for email verification token")
		}
		claim = emailClaims
	default:
		return "", errors.New("unsupported token type")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	tokenString, err := token.SignedString([]byte(TokenSecretKey))

	return tokenString, err
}

// TokenParse parses token, validates it and returns the claims from the token or an error.
func TokenParse(accessToken string, tokenType enums.TokenType) (interface{}, error) {
	var claim jwt.Claims

	switch tokenType {
	case enums.Access:
		claim = &claims.AccessClaims{}
	case enums.PasswordReset:
		claim = &claims.PasswordResetClaims{}
	case enums.EmailVerification:
		claim = &claims.EmailVerificationClaims{}
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
	case *claims.EmailVerificationClaims:
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
func TokenCreateAccessClaim(user *models.User, app, deviceID string) claims.AccessClaims {
	claim := claims.AccessClaims{
		IdentityClaims: claims.IdentityClaims{
			Id:       int(user.ID),
			App:      app,
			DeviceID: deviceID,
		},
		IsEmailVerified: user.EmailVerifiedAt.Valid,
		IsPhoneVerified: user.PhoneVerifiedAt.Valid,
		IsTempPassword:  user.IsTempPassword,
		Apps:            make(map[string]map[string][]string),
		Type:            enums.Access,
	}

	for i := range user.AppRoles {
		var appName = utils.PascalCaseToCamelcase(user.AppRoles[i].AppName)
		var roleName = utils.PascalCaseToCamelcase(user.AppRoles[i].RoleName)
		if _, ok := claim.Apps[appName]; !ok {
			claim.Apps[appName] = map[string][]string{}
		}
		if _, ok := claim.Apps[appName][roleName]; !ok {
			claim.Apps[appName][roleName] = []string{}
		}

		claim.Apps[appName][roleName] = append(claim.Apps[appName][roleName], user.AppRoles[i].PermissionName)
	}

	return claim
}

// TokenCreatePasswordResetClaim creates a new password reset claim from the given user.
func TokenCreatePasswordResetClaim(userID uint, app, deviceID string) claims.PasswordResetClaims {
	return claims.PasswordResetClaims{
		IdentityClaims: claims.IdentityClaims{
			Id:       int(userID),
			App:      app,
			DeviceID: deviceID,
		},
		Type: enums.PasswordReset,
	}
}

// TokenCreateEmailVerificationClaim creates a new email verification claim from the given user.
func TokenCreateEmailVerificationClaim(userID uint, app, deviceID, email string) claims.EmailVerificationClaims {
	return claims.EmailVerificationClaims{
		IdentityClaims: claims.IdentityClaims{
			Id:       int(userID),
			App:      app,
			DeviceID: deviceID,
		},
		Type:  enums.EmailVerification,
		Email: email,
	}
}

// TokenFromCache returns the token from the cache.
func TokenFromCache(app, deviceID string, userID uint, tokenType enums.TokenType) (string, error) {
	key := cacheKey(app, deviceID, userID, tokenType)

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
func TokenToCache(app, deviceID string, userID uint, token string, exp time.Time, tokenType enums.TokenType) error {
	key := cacheKey(app, deviceID, userID, tokenType)

	if result := cache.Valkey.Do(context.Background(), cache.Valkey.B().Set().Key(key).Value(token).Exat(exp).Build()); result.Error() != nil {
		return result.Error()
	} else {
		return nil
	}
}

// TokenDeleteAllFromCache deletes all tokens from the cache for a given app, userID, and tokenType.
func TokenDeleteAllFromCache(app string, userID uint, tokenType enums.TokenType) error {
	// Construct the pattern to match keys in the cache.
	var pattern string
	switch tokenType {
	case enums.Access:
		pattern = fmt.Sprintf("%s:%d:*:AccessToken", app, userID)
	case enums.PasswordReset:
		pattern = fmt.Sprintf("%s:%d:*:PasswordResetToken", app, userID)
	case enums.EmailVerification:
		pattern = fmt.Sprintf("%s:%d:*:EmailVerificationToken", app, userID)
	default:
		return errors.New("unsupported token type")
	}

	ctx := context.Background()
	cursor := uint64(0) // Start with cursor 0 for SCAN

	for {
		// Perform the SCAN command with the current cursor and pattern.
		result := cache.Valkey.Do(ctx, cache.Valkey.B().Scan().Cursor(cursor).Match(pattern).Build())
		if result.Error() != nil {
			return result.Error()
		}

		// Parse the result to get the next cursor and keys.
		scanResult, err := result.AsScanEntry()
		if err != nil {
			return err
		}

		// Delete each key returned by the SCAN command.
		for _, key := range scanResult.Elements {
			if delResult := cache.Valkey.Do(ctx, cache.Valkey.B().Del().Key(key).Build()); delResult.Error() != nil {
				return delResult.Error()
			}
		}

		// If the cursor is 0, the iteration is complete.
		if scanResult.Cursor == 0 {
			break
		}

		// Update the cursor for the next iteration.
		cursor = scanResult.Cursor
	}

	return nil
}

// TokenDeleteFromCache deletes the token from the cache.
func TokenDeleteFromCache(app, deviceID string, userID uint, tokenType enums.TokenType) error {
	key := cacheKey(app, deviceID, userID, tokenType)

	if result := cache.Valkey.Do(context.Background(), cache.Valkey.B().Del().Key(key).Build()); result.Error() != nil {
		return result.Error()
	} else {
		return nil
	}
}

// TokenExistsInCache checks if the token exists in the cache.
func TokenExistsInCache(app, deviceID string, userID uint, tokenType enums.TokenType) (bool, error) {
	key := cacheKey(app, deviceID, userID, tokenType)

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
func cacheKey(app, deviceID string, userID uint, tokenType enums.TokenType) string {
	var key string

	switch tokenType {
	case enums.Access:
		key = tokenCacheKey(app, deviceID, userID)
	case enums.PasswordReset:
		key = tokenPasswordResetCacheKey(app, deviceID, userID)
	case enums.EmailVerification:
		key = tokenEmailVerificationCacheKey(app, deviceID, userID)
	}

	return key
}

// tokenCacheKey returns the key for the token cache.
func tokenCacheKey(app, deviceID string, userID uint) string {
	return fmt.Sprintf("%s:%d:%s:AccessToken", app, userID, deviceID)
}

// tokenPasswordResetCacheKey returns the key for password reset token cache.
func tokenPasswordResetCacheKey(app, deviceID string, userID uint) string {
	return fmt.Sprintf("%s:%d:%s:PasswordResetToken", app, userID, deviceID)
}

// tokenEmailVerificationCacheKey returns the key for email verification token cache.
func tokenEmailVerificationCacheKey(app, deviceID string, userID uint) string {
	return fmt.Sprintf("%s:%d:%s:EmailVerificationToken", app, userID, deviceID)
}
