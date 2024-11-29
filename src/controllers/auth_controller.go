package controllers

import (
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

	// Check if password is empty.
	if signIn.Password == "" {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.PasswordEmpty, "Password is empty.")
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
	token, exp, err := services.TokenCreate(services.TokenCreateAccessClaim(&user), services.TokenAccessExpireMinutes, time.Minute, enums.Access)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.TokenCreate, err)
	}

	if err = services.TokenToCache(signIn.App, user.ID, token, exp.Time); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.CacheError, err)
	}

	// Set user activity.
	if err := services.SetLastLoginAt(signIn.App, user.ID, time.Now().UTC()); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err)
	}

	// Create a new response.
	response := &responses.UsernamePasswordSignIn{}
	response.SetUsernamePasswordSignIn(&user, token, exp, refreshToken)

	return c.JSON(response)
}
