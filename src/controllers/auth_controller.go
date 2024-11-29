package controllers

import (
	"api-auth/main/src/claims"
	"api-auth/main/src/dto/requests"
	"api-auth/main/src/dto/responses"
	"api-auth/main/src/enums"
	"api-auth/main/src/errors"
	"api-auth/main/src/services"
	errorutil "github.com/ArnoldPMolenaar/api-utils/errors"
	"github.com/ArnoldPMolenaar/api-utils/utils"
	"github.com/gofiber/fiber/v2"
	"time"
)

// SignUp method to create a new user.
func SignUp(c *fiber.Ctx) error {
	// Create a new user auth struct.
	signUp := &requests.SignUp{}

	// Check, if received JSON data is parsed.
	if err := c.BodyParser(signUp); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.BodyParse, err.Error())
	}

	// Validate signUp fields.
	validate := utils.NewValidator()
	if err := validate.Struct(signUp); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.Validator, utils.ValidatorErrors(err))
	}

	// Check if app exists.
	if available, err := services.IsAppAvailable(signUp.App); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.UsernameExists, "AppName does not exist.")
	}

	// Check if user already exists.
	if available, err := services.IsUsernameAvailable(signUp.Username); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.UsernameExists, "Username already exists.")
	}

	if available, err := services.IsEmailAvailable(signUp.Email); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.EmailExists, "Email already exists.")
	}

	if signUp.PhoneNumber != nil {
		if available, err := services.IsPhoneNumberAvailable(signUp.PhoneNumber); err != nil {
			return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
		} else if !available {
			return errorutil.Response(c, fiber.StatusBadRequest, errors.PhoneNumberExists, "Phone already exists.")
		}
	}

	// Create a new user.
	if user, err := services.SignUp(signUp); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else {
		return c.JSON(user)
	}
}

func UsernamePasswordSignIn(c *fiber.Ctx) error {
	// Create a new user auth struct.
	signIn := &requests.UsernamePasswordSignIn{}

	// Check, if received JSON data is parsed.
	if err := c.BodyParser(signIn); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.BodyParse, err.Error())
	}

	// Validate signIn fields.
	validate := utils.NewValidator()
	if err := validate.Struct(signIn); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.Validator, utils.ValidatorErrors(err))
	}

	// Check if app exists.
	if available, err := services.IsAppAvailable(signIn.App); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.UsernameExists, "AppName does not exist.")
	}

	// Check if user exists.
	if active, err := services.IsUserActive(signIn.Username); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if !active {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.UsernameEmailUnknown, "Username and Email is unknown.")
	}

	// Check if user has this recipe.
	if hasRecipe, err := services.HasUserRecipe(signIn.App, signIn.Username, enums.UsernamePassword); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if !hasRecipe {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.RecipeNotAllowed, "Username does not have this recipe.")
	}

	// Check if password is correct.
	if correct, err := services.IsPasswordCorrect(signIn.Username, signIn.Password); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if !correct {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.PasswordIncorrect, "Password is incorrect.")
	}

	// Get the user.
	user, err := services.GetUserByUsername(signIn.Username)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err)
	}

	// Generate a new refresh token.
	refreshToken, err := services.RotateRefreshToken(signIn.App, user.ID)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err)
	}

	// Generate a new access token.
	accessToken, exp, err := services.TokenCreate(services.TokenCreateAccessClaim(&user, signIn.App), services.TokenAccessExpireMinutes, time.Minute, enums.Access)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.TokenCreate, err)
	}

	// Save the token to the cache.
	if err = services.TokenToCache(signIn.App, user.ID, accessToken, exp.Time); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.CacheError, err)
	}

	// Set user activity.
	if err := services.SetLastLoginAt(signIn.App, user.ID, time.Now().UTC()); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err)
	}

	// Create a new response.
	response := &responses.UsernamePasswordSignIn{}
	response.SetUsernamePasswordSignIn(&user, accessToken, exp, refreshToken)

	return c.JSON(response)
}

func Token(c *fiber.Ctx) error {
	// Get app and userID from claims.
	claim := c.Locals("claims")
	if claim == nil {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Claims not found.")
	}

	accessClaims, ok := claim.(*claims.AccessClaims)
	if !ok {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Invalid claims type.")
	}

	// Get the user.
	user, err := services.GetUserByID(uint(accessClaims.Id))
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err)
	}

	// Generate a new refresh token.
	refreshToken, err := services.RotateRefreshToken(accessClaims.App, user.ID)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err)
	}

	// Generate a new access token.
	accessToken, exp, err := services.TokenCreate(services.TokenCreateAccessClaim(&user, accessClaims.App), services.TokenAccessExpireMinutes, time.Minute, enums.Access)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.TokenCreate, err)
	}

	// Save the token to the cache.
	if err = services.TokenToCache(accessClaims.App, user.ID, accessToken, exp.Time); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.CacheError, err)
	}

	// Set user activity.
	if err := services.SetLastLoginAt(accessClaims.App, user.ID, time.Now().UTC()); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err)
	}

	// Create a new response.
	response := &responses.RefreshToken{}
	response.SetAccessToken(accessToken, exp)
	response.SetRefreshToken(refreshToken)

	return c.JSON(response)
}

// RefreshToken method to refresh the access token.
// This endpoint is unsecured. So we don't rotate the refresh token.
// When the refresh-token is used on this endpoint, the refresh-token is deleted.
func RefreshToken(c *fiber.Ctx) error {
	// Create a new refresh token struct.
	token := &requests.RefreshToken{}

	// Check, if received JSON data is parsed.
	if err := c.BodyParser(token); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.BodyParse, err.Error())
	}

	// Validate token fields.
	validate := utils.NewValidator()
	if err := validate.Struct(token); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.Validator, utils.ValidatorErrors(err))
	}

	// Check if refresh token exists.
	if valid, err := services.IsRefreshTokenValid(token.UserID, token.App, token.RefreshToken); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if !valid {
		// Destroy session against replay attacks.
		if err := services.DestroyUserSessions(token.UserID); err != nil {
			return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
		}

		return errorutil.Response(c, fiber.StatusUnauthorized, errors.TokenRefreshInvalid, "Refresh token is invalid.")
	}

	// Get the user.
	user, err := services.GetUserByID(token.UserID)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err)
	}

	// Delete the refresh token.
	if err := services.DeleteRefreshToken(token.App, token.UserID); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err)
	}

	// Generate a new access token.
	accessToken, exp, err := services.TokenCreate(services.TokenCreateAccessClaim(&user, token.App), services.TokenAccessExpireMinutes, time.Minute, enums.Access)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.TokenCreate, err)
	}

	// Save the token to the cache.
	if err = services.TokenToCache(token.App, user.ID, accessToken, exp.Time); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.CacheError, err)
	}

	// Set user activity.
	if err := services.SetLastLoginAt(token.App, user.ID, time.Now().UTC()); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err)
	}

	// Create a new response.
	response := &responses.RefreshToken{}
	response.SetAccessToken(accessToken, exp)

	return c.JSON(response)
}

// TokenVerify method to verify the token.
// This endpoint is empty, because the middleware already verified the token.
// It is only used to validate the active cache session.
// This endpoint needs to be empty and very fast.
func TokenVerify(c *fiber.Ctx) error {
	return c.SendStatus(fiber.StatusNoContent)
}
