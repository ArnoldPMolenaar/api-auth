package middleware

import (
	"api-auth/main/src/claims"
	"api-auth/main/src/enums"
	errorint "api-auth/main/src/errors"
	"api-auth/main/src/services"
	errorsutil "github.com/ArnoldPMolenaar/api-utils/errors"
	"github.com/gofiber/fiber/v2"
	"time"
)

// PasswordProtected middleware checks if the password reset token is valid.
func PasswordProtected() func(*fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		// Get the token from the header.
		resetToken, err := getTokenFromHeader(c)
		if err != nil {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorint.TokenExtraction,
				"Reset token could not be read from header.",
			)
		}
		if resetToken == "" {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Reset token is empty.",
			)
		}

		// Get the claims of the token.
		claim, err := services.TokenParse(resetToken, enums.PasswordReset)
		if err != nil {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Invalid reset token.",
			)
		}

		resetClaims, ok := claim.(*claims.PasswordResetClaims)
		if !ok || resetClaims.Type != enums.PasswordReset {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Invalid reset token claims.",
			)
		}

		// Double check for expiration for testing purposes.
		if resetClaims.ExpiresAt.Unix() < time.Now().UTC().Unix() {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Outdated reset token.",
			)
		}

		// Check if token exists in the cache.
		if exists, err := services.TokenExistsInCache(resetClaims.App, resetClaims.DeviceID, uint(resetClaims.Id), enums.PasswordReset); err != nil {
			return errorsutil.Response(
				c,
				fiber.StatusInternalServerError,
				errorsutil.CacheError,
				err.Error(),
			)
		} else if !exists {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Reset token does not exist.",
			)
		}

		// Check if token is equal to the one in the cache.
		if token, err := services.TokenFromCache(resetClaims.App, resetClaims.DeviceID, uint(resetClaims.Id), enums.PasswordReset); err != nil {
			return errorsutil.Response(
				c,
				fiber.StatusInternalServerError,
				errorsutil.CacheError,
				err.Error(),
			)
		} else if token != resetToken {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Reset token does not match.",
			)
		}

		// Set the claims to the context.
		c.Locals("claims", resetClaims)

		return c.Next()
	}
}
