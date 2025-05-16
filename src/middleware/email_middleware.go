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

// EmailProtected middleware checks if the email verification token is valid.
func EmailProtected() func(*fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		// Get the token from the header.
		emailToken, err := getTokenFromHeader(c)
		if err != nil {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorint.TokenExtraction,
				"Email token could not be read from header.",
			)
		}
		if emailToken == "" {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Email token is empty.",
			)
		}

		// Get the claims of the token.
		claim, err := services.TokenParse(emailToken, enums.EmailVerification)
		if err != nil {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Invalid email token.",
			)
		}

		emailClaims, ok := claim.(*claims.EmailVerificationClaims)
		if !ok || emailClaims.Type != enums.EmailVerification {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Invalid email token claims.",
			)
		}

		// Double check for expiration for testing purposes.
		if emailClaims.ExpiresAt.Unix() < time.Now().UTC().Unix() {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Outdated email token.",
			)
		}

		// Check if token exists in the cache.
		if exists, err := services.TokenExistsInCache(emailClaims.App, emailClaims.DeviceID, uint(emailClaims.Id), enums.EmailVerification); err != nil {
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
				"Email token does not exist.",
			)
		}

		// Check if token is equal to the one in the cache.
		if token, err := services.TokenFromCache(emailClaims.App, emailClaims.DeviceID, uint(emailClaims.Id), enums.EmailVerification); err != nil {
			return errorsutil.Response(
				c,
				fiber.StatusInternalServerError,
				errorsutil.CacheError,
				err.Error(),
			)
		} else if token != emailToken {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Email token does not match.",
			)
		}

		// Check if the email exists.
		if available, err := services.IsEmailAvailable(emailClaims.Email); err != nil {
			return errorsutil.Response(
				c,
				fiber.StatusInternalServerError,
				errorsutil.QueryError,
				err.Error(),
			)
		} else if available {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Email does not exist.",
			)
		}

		// Check if the email is verified.
		if verified, err := services.IsEmailVerified(emailClaims.Email); err != nil {
			return errorsutil.Response(
				c,
				fiber.StatusInternalServerError,
				errorsutil.QueryError,
				err.Error(),
			)
		} else if verified {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Email is already verified.",
			)
		}

		// Set the claims to the context.
		c.Locals("claims", emailClaims)

		return c.Next()
	}
}
