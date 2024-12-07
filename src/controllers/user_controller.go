package controllers

import (
	"api-auth/main/src/dto/requests"
	"api-auth/main/src/dto/responses"
	"api-auth/main/src/errors"
	"api-auth/main/src/services"
	"api-auth/main/src/utils"
	errorutil "github.com/ArnoldPMolenaar/api-utils/errors"
	util "github.com/ArnoldPMolenaar/api-utils/utils"
	"github.com/gofiber/fiber/v2"
)

// GetUserRecipesByUsername method to get user recipes by username.
func GetUserRecipesByUsername(c *fiber.Ctx) error {
	values := c.Request().URI().QueryArgs()
	app := string(values.Peek("app"))
	username := string(values.Peek("username"))

	// Check if user exists.
	if active, err := services.IsUserActive(username); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if !active {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.UsernameEmailUnknown, "Username and Email is unknown.")
	}

	// Get user recipes.
	if recipes, err := services.GetUserRecipesByUsername(app, username); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else {
		return c.JSON(recipes)
	}
}

// GetUser method to get user by ID.
func GetUser(c *fiber.Ctx) error {
	// Get the userID parameter from the URL.
	userIDParam := c.Params("id")
	if userIDParam == "" {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.MissingRequiredParam, "User ID is required.")
	}
	userID, err := utils.StringToUint(userIDParam)
	if err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.InvalidParam, "Invalid User ID.")
	}

	// Get the user.
	user, err := services.GetUserByID(userID)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// Return the user.
	response := responses.User{}
	response.SetUser(&user)

	return c.JSON(response)
}

// UpdateUser method to update user by ID.
func UpdateUser(c *fiber.Ctx) error {
	// Get the userID parameter from the URL.
	userIDParam := c.Params("id")
	if userIDParam == "" {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.MissingRequiredParam, "User ID is required.")
	}
	userID, err := utils.StringToUint(userIDParam)
	if err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.InvalidParam, "Invalid User ID.")
	}

	// Get the request body.
	requestUser := &requests.UpdateUser{}
	if err := c.BodyParser(requestUser); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.BodyParse, "Invalid request body.")
	}

	// Validate user fields.
	validate := util.NewValidator()
	if err := validate.Struct(requestUser); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.Validator, util.ValidatorErrors(err))
	}
	for _, item := range requestUser.Roles {
		if err := validate.Struct(item); err != nil {
			return errorutil.Response(c, fiber.StatusBadRequest, errors.Validator, util.ValidatorErrors(err))
		}
	}
	for _, item := range requestUser.Recipes {
		if err := validate.Struct(item); err != nil {
			return errorutil.Response(c, fiber.StatusBadRequest, errors.Validator, util.ValidatorErrors(err))
		}
	}

	// Get the user.
	user, err := services.GetUserByID(userID)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// Check if user already exists.
	if requestUser.Username != user.Username {
		if available, err := services.IsUsernameAvailable(requestUser.Username); err != nil {
			return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
		} else if !available {
			return errorutil.Response(c, fiber.StatusBadRequest, errors.UsernameExists, "Username already exists.")
		}
	}

	if requestUser.Email != user.Email {
		if available, err := services.IsEmailAvailable(requestUser.Email); err != nil {
			return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
		} else if !available {
			return errorutil.Response(c, fiber.StatusBadRequest, errors.EmailExists, "Email already exists.")
		}
	}

	if requestUser.PhoneNumber != nil && *requestUser.PhoneNumber != *user.PhoneNumber {
		if available, err := services.IsPhoneNumberAvailable(requestUser.PhoneNumber); err != nil {
			return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
		} else if !available {
			return errorutil.Response(c, fiber.StatusBadRequest, errors.PhoneNumberExists, "Phone already exists.")
		}
	}

	// Check if the user data has been modified since it was last fetched.
	if requestUser.UpdatedAt.Unix() < user.UpdatedAt.Unix() {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.OutOfSync, "Data is out of sync.")
	}

	// Update the user.
	updatedUser, err := services.UpdateUser(&user, requestUser)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	}

	// Return the user.
	response := responses.User{}
	response.SetUser(updatedUser)

	return c.JSON(response)
}

// DeleteUser method to delete user by ID.
func DeleteUser(c *fiber.Ctx) error {
	// Get the userID parameter from the URL.
	userIDParam := c.Params("id")
	if userIDParam == "" {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.MissingRequiredParam, "User ID is required.")
	}
	userID, err := utils.StringToUint(userIDParam)
	if err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.InvalidParam, "Invalid User ID.")
	}

	// Get the user.
	user, err := services.GetUserByID(userID)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// Delete the user.
	if err := services.DeleteUser(user.ID); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	}

	return c.SendStatus(fiber.StatusNoContent)
}
