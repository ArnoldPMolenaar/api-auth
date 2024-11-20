package controllers

import (
	"api-auth/main/src/dto/requests"
	"api-auth/main/src/errors"
	"api-auth/main/src/services"
	errorutil "github.com/ArnoldPMolenaar/api-utils/errors"
	"github.com/ArnoldPMolenaar/api-utils/utils"
	"github.com/gofiber/fiber/v2"
)

// Signup method to create a new user.
func Signup(c *fiber.Ctx) error {
	// Create a new user auth struct.
	signUp := &requests.Signup{}

	// Check, if received JSON data is parsed.
	if err := c.BodyParser(signUp); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.BodyParse, err.Error())
	}

	// Validate log fields.
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
	if user, err := services.UsernamePasswordSignup(signUp); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else {
		return c.JSON(user)
	}
}
