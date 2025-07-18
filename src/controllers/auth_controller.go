package controllers

import (
	"api-auth/main/src/claims"
	"api-auth/main/src/dto/requests"
	"api-auth/main/src/dto/responses"
	"api-auth/main/src/enums"
	"api-auth/main/src/errors"
	"api-auth/main/src/models"
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
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.BodyParse, err.Error())
	}

	// Validate signUp fields.
	validate := utils.NewValidator()
	if err := validate.Struct(signUp); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.Validator, utils.ValidatorErrors(err))
	}

	for i := range signUp.Recipes {
		if available, err := services.IsAppAvailable(signUp.Recipes[i].App); err != nil {
			return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
		} else if !available {
			return errorutil.Response(c, fiber.StatusBadRequest, errors.AppExists, "AppName does not exist.")
		}
	}

	// Check if user already exists.
	if available, err := services.IsUsernameAvailable(signUp.Username); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.UsernameExists, "Username already exists.")
	}

	if available, err := services.IsEmailAvailable(signUp.Email); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.EmailExists, "Email already exists.")
	}

	if signUp.PhoneNumber != nil {
		if available, err := services.IsPhoneNumberAvailable(signUp.PhoneNumber); err != nil {
			return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
		} else if !available {
			return errorutil.Response(c, fiber.StatusBadRequest, errors.PhoneNumberExists, "Phone already exists.")
		}
	}

	// Create a new user.
	if user, err := services.SignUp(signUp); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else {
		return c.JSON(user)
	}
}

func UsernamePasswordSignIn(c *fiber.Ctx) error {
	// Create a new user auth struct.
	signIn := &requests.UsernamePasswordSignIn{}

	// Check, if received JSON data is parsed.
	if err := c.BodyParser(signIn); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.BodyParse, err.Error())
	}

	// Validate signIn fields.
	validate := utils.NewValidator()
	if err := validate.Struct(signIn); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.Validator, utils.ValidatorErrors(err))
	}

	// Check if app exists.
	if available, err := services.IsAppAvailable(signIn.App); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.AppExists, "AppName does not exist.")
	}

	// Check if user exists.
	if active, err := services.IsUserActive(signIn.Username); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if !active {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.UsernameEmailUnknown, "Username and Email is unknown.")
	}

	// Check if user has this recipe.
	if hasRecipe, err := services.HasUserRecipe(signIn.App, signIn.Username, enums.UsernamePassword); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if !hasRecipe {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.RecipeNotAllowed, "Username does not have this recipe.")
	}

	// Check if password is correct.
	if correct, err := services.IsPasswordCorrect(signIn.Username, signIn.Password); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if !correct {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.PasswordIncorrect, "Password is incorrect.")
	}

	// Get the user.
	user, err := services.GetUserByUsername(signIn.Username)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err)
	}

	// Generate a new access token.
	accessToken, exp, err := services.TokenCreate(
		services.TokenCreateAccessClaim(&user, signIn.App, signIn.DeviceID),
		services.TokenAccessExpireMinutes,
		time.Minute,
		enums.Access)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.TokenCreate, err)
	}

	// Save the token to the cache.
	if err = services.TokenToCache(signIn.App, signIn.DeviceID, user.ID, accessToken, exp.Time, enums.Access); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.CacheError, err)
	}

	// Set user activity.
	if err := services.SetLastLoginAt(signIn.App, user.ID, time.Now().UTC()); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err)
	}

	// Create a new response.
	response := &responses.UsernamePasswordSignIn{}
	response.SetUsernamePasswordSignIn(&user, accessToken, exp)

	return c.JSON(response)
}

// GetSignedInUser read the header key Authorization and gives the signed-in user.
func GetSignedInUser(c *fiber.Ctx) error {
	// Get userID from claims.
	authHeader := c.Get("Authorization")
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
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err)
	}

	// Create a new response.
	response := &responses.UsernamePasswordSignIn{}
	response.SetUsernamePasswordSignIn(&user, authHeader, accessClaims.ExpiresAt)

	return c.JSON(response)
}

// Token method to create a new access token and invalidate the old one.
// Used to refresh the session.
func Token(c *fiber.Ctx) error {
	// Get deviceID from query.
	deviceID := c.Query("deviceId")

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
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err)
	}

	// Generate a new refresh token.
	var refreshToken *models.UserAppRefreshToken
	if deviceID != "" {
		if used, err := services.IsRefreshTokenUsed(user.ID, accessClaims.App, deviceID); err != nil {
			return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err)
		} else if used {
			refreshToken, err = services.RotateRefreshToken(accessClaims.App, deviceID, user.ID)
			if err != nil {
				return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err)
			}
		}
	}

	// Generate a new access token.
	accessToken, exp, err := services.TokenCreate(
		services.TokenCreateAccessClaim(&user, accessClaims.App, accessClaims.DeviceID),
		services.TokenAccessExpireMinutes,
		time.Minute,
		enums.Access)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.TokenCreate, err)
	}

	// Save the token to the cache.
	if err = services.TokenToCache(accessClaims.App, deviceID, user.ID, accessToken, exp.Time, enums.Access); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.CacheError, err)
	}

	// Set user activity.
	if err := services.SetLastLoginAt(accessClaims.App, user.ID, time.Now().UTC()); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err)
	}

	// Create a new response.
	response := &responses.RefreshToken{}
	response.SetAccessToken(accessToken, exp)
	response.SetRefreshToken(refreshToken)

	return c.JSON(response)
}

// CreateRefreshToken method to create a new refresh token.
func CreateRefreshToken(c *fiber.Ctx) error {
	// Get deviceID from query.
	deviceID := c.Query("deviceId")
	if deviceID == "" {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.InvalidParam, "Device ID is required.")
	}

	// Get app and userID from claims.
	claim := c.Locals("claims")
	if claim == nil {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Claims not found.")
	}

	accessClaims, ok := claim.(*claims.AccessClaims)
	if !ok {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Invalid claims type.")
	}

	// Generate a new refresh token.
	refreshToken, err := services.RotateRefreshToken(accessClaims.App, deviceID, uint(accessClaims.Id))
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err)
	}

	// Create a new response.
	response := &responses.Token{}
	response.SetToken(refreshToken.Token, refreshToken.ValidUntil)

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
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.BodyParse, err.Error())
	}

	// Validate token fields.
	validate := utils.NewValidator()
	if err := validate.Struct(token); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.Validator, utils.ValidatorErrors(err))
	}

	// Check if refresh token exists.
	if valid, err := services.IsRefreshTokenValid(token.UserID, token.DeviceID, token.App, token.RefreshToken); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if !valid {
		// Destroy session against replay attacks.
		if err := services.DestroyUserSessions(token.UserID); err != nil {
			return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
		}

		return errorutil.Response(c, fiber.StatusUnauthorized, errors.TokenRefreshInvalid, "Refresh token is invalid.")
	}

	// Get the user.
	user, err := services.GetUserByID(token.UserID)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err)
	}

	// Delete the refresh token.
	if err := services.DeleteRefreshToken(token.App, token.DeviceID, token.UserID); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err)
	}

	// Generate a new access token.
	accessToken, exp, err := services.TokenCreate(services.TokenCreateAccessClaim(&user, token.App, token.DeviceID),
		services.TokenAccessExpireMinutes,
		time.Minute,
		enums.Access)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.TokenCreate, err)
	}

	// Save the token to the cache.
	if err = services.TokenToCache(token.App, token.DeviceID, user.ID, accessToken, exp.Time, enums.Access); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.CacheError, err)
	}

	// Set user activity.
	if err := services.SetLastLoginAt(token.App, user.ID, time.Now().UTC()); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err)
	}

	// Create a new response.
	// The refresh-token endpoint has the same behavior as a clean sign-in.
	response := &responses.UsernamePasswordSignIn{}
	response.SetUsernamePasswordSignIn(&user, accessToken, exp)

	return c.JSON(response)
}

// TokenVerify method to verify the token.
// This endpoint is empty, because the middleware already verified the token.
// It is only used to validate the active cache session.
// This endpoint needs to be empty and very fast.
func TokenVerify(c *fiber.Ctx) error {
	return c.SendStatus(fiber.StatusNoContent)
}

// SignOut method to sign out the user.
// Also deletes the refresh-token because of explicit sign-out.
func SignOut(c *fiber.Ctx) error {
	// Create a new signOut request.
	signOut := &requests.SignOut{}

	// Check, if received JSON data is parsed.
	if err := c.BodyParser(signOut); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.BodyParse, err.Error())
	}

	// Validate signOut fields.
	validate := utils.NewValidator()
	if err := validate.Struct(signOut); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.Validator, utils.ValidatorErrors(err))
	}

	// Get app and userID from claims.
	claim := c.Locals("claims")
	if claim == nil {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Claims not found.")
	}

	accessClaims, ok := claim.(*claims.AccessClaims)
	if !ok {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Invalid claims type.")
	}

	// Delete the refresh token.
	if err := services.DeleteRefreshToken(accessClaims.App, signOut.DeviceID, uint(accessClaims.Id)); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err)
	}

	// Delete the access token from the cache.
	if err := services.TokenDeleteFromCache(accessClaims.App, signOut.DeviceID, uint(accessClaims.Id), enums.Access); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.CacheError, err)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// TokenPasswordReset method to create a new password reset token.
func TokenPasswordReset(c *fiber.Ctx) error {
	// Create a new password reset struct.
	token := &requests.PasswordReset{}

	// Check, if received JSON data is parsed.
	if err := c.BodyParser(token); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.BodyParse, err.Error())
	}

	// Validate token fields.
	validate := utils.NewValidator()
	if err := validate.Struct(token); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.Validator, utils.ValidatorErrors(err))
	}

	// Check if app exists.
	if available, err := services.IsAppAvailable(token.App); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.AppExists, "AppName does not exist.")
	}

	// Get the user.
	user, err := services.GetUserByEmail(token.Email)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err)
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errors.EmailUnknown, "Email is unknown.")
	}

	// Generate a new password reset token.
	passwordResetToken, exp, err := services.TokenCreate(services.TokenCreatePasswordResetClaim(user.ID, token.App, token.DeviceID), services.TokenPasswordResetExpireMinutes, time.Minute, enums.PasswordReset)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.TokenCreate, err)
	}

	// Save the token to the cache.
	if err = services.TokenToCache(token.App, token.DeviceID, user.ID, passwordResetToken, exp.Time, enums.PasswordReset); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.CacheError, err)
	}

	// Create a new response.
	response := &responses.PasswordReset{}
	response.SetPasswordReset(user.ID, passwordResetToken, exp)

	return c.JSON(response)
}

// TokenPasswordResetVerify method to verify the reset password token.
// This endpoint is empty, because the middleware already verified the token.
// It is only used to validate the active password reset.
// This endpoint needs to be empty and very fast.
func TokenPasswordResetVerify(c *fiber.Ctx) error {
	return c.SendStatus(fiber.StatusNoContent)
}

// TokenEmailVerification method to create a new email verification token.
func TokenEmailVerification(c *fiber.Ctx) error {
	// Create a new emailVerification request.
	emailVerification := &requests.EmailVerification{}

	// Check, if received JSON data is parsed.
	if err := c.BodyParser(emailVerification); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.BodyParse, err.Error())
	}

	// Validate emailVerification fields.
	validate := utils.NewValidator()
	if err := validate.Struct(emailVerification); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.Validator, utils.ValidatorErrors(err))
	}

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
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err)
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// Generate a new email verification token.
	emailVerificationToken, exp, err := services.TokenCreate(
		services.TokenCreateEmailVerificationClaim(user.ID, accessClaims.App, emailVerification.DeviceID, user.Email),
		services.TokenEmailVerificationExpireHours,
		time.Hour,
		enums.EmailVerification)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.TokenCreate, err)
	}

	// Save the token to the cache.
	if err = services.TokenToCache(accessClaims.App, emailVerification.DeviceID, user.ID, emailVerificationToken, exp.Time, enums.EmailVerification); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.CacheError, err)
	}

	// Create a new response.
	response := &responses.EmailVerification{}
	response.SetEmailVerification(user.ID, user.Email, emailVerificationToken, exp)

	return c.JSON(response)
}

// TokenEmailVerificationVerify method to verify the email verification token.
// This endpoint is empty, because the middleware already verified the token.
// It is only used to validate the active email verification.
// This endpoint needs to be empty and very fast.
func TokenEmailVerificationVerify(c *fiber.Ctx) error {
	return c.SendStatus(fiber.StatusNoContent)
}
