package controllers

import (
	"api-auth/main/src/dto/responses"
	"api-auth/main/src/errors"
	"api-auth/main/src/services"
	"api-auth/main/src/utils"
	errorutil "github.com/ArnoldPMolenaar/api-utils/errors"
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
	}
	if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// Return the user.
	response := responses.User{}
	response.SetUser(&user)

	return c.JSON(response)
}
