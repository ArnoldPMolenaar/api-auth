package middleware

import (
	"api-auth/main/src/claims"
	"api-auth/main/src/enums"
	errorint "api-auth/main/src/errors"
	"api-auth/main/src/services"
	"errors"
	errorsutil "github.com/ArnoldPMolenaar/api-utils/errors"
	"github.com/gofiber/fiber/v2"
	"strings"
	"time"
)

// JWTProtected middleware checks if the access token is valid.
// Also checks if the user is not blocked.
func JWTProtected() func(*fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		// Get the token from the header.
		accessToken, err := getTokenFromHeader(c)
		if err != nil {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorint.TokenExtraction,
				"Access token could not be read from header.",
			)
		}
		if accessToken == "" {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Access token is invalid.",
			)
		}

		// Get the claims of the token.
		claim, err := services.TokenParse(accessToken, enums.Access)
		if err != nil {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Invalid access token.",
			)
		}

		accessClaims, ok := claim.(*claims.AccessClaims)
		if !ok || accessClaims.Type != enums.Access {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Invalid access token claims.",
			)
		}

		// Double check for expiration for testing purposes.
		if accessClaims.ExpiresAt.Unix() < time.Now().UTC().Unix() {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Outdated access token.",
			)
		}

		// Check if token exists in the cache.
		if exists, err := services.TokenExistsInCache(accessClaims.App, uint(accessClaims.Id)); err != nil {
			return errorsutil.Response(
				c,
				fiber.StatusInternalServerError,
				errorint.CacheError,
				err.Error(),
			)
		} else if !exists {
			return errorsutil.Response(
				c,
				fiber.StatusUnauthorized,
				errorsutil.Unauthorized,
				"Access token does not exist.",
			)
		}

		// Check for blocked permission
		if accessClaims.Roles["blocked"] != nil {
			return errorsutil.Response(
				c,
				fiber.StatusForbidden,
				errorint.Forbidden,
				"User is blocked",
			)
		}

		// Set the claims to the context.
		c.Locals("claims", accessClaims)

		return c.Next()
	}
}

// getTokenFromHeader function to get the token from the header.
// Also validates the token format.
func getTokenFromHeader(c *fiber.Ctx) (string, error) {
	headerValue := c.Get("Authorization")
	if headerValue == "" {
		return "", nil
	}

	headerValues := strings.Fields(headerValue)
	if len(headerValues) != 2 || strings.ToLower(headerValues[0]) != "bearer" {
		return "", errors.New(errorint.TokenNoBearerAuthorizationHeaderFormat)
	}

	return headerValues[1], nil
}