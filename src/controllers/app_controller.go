package controllers

import (
	"api-auth/main/src/dto/requests"
	"api-auth/main/src/dto/responses"
	"api-auth/main/src/services"

	errorutil "github.com/ArnoldPMolenaar/api-utils/errors"
	"github.com/ArnoldPMolenaar/api-utils/utils"
	"github.com/gofiber/fiber/v3"
)

// CreateApp method to create an app.
func CreateApp(c fiber.Ctx) error {
	// Parse the request.
	request := requests.CreateApp{}
	if err := c.Bind().Body(&request); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.BodyParse, err.Error())
	}

	// Validate app fields.
	validate := utils.NewValidator()
	if err := validate.Struct(request); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.Validator, utils.ValidatorErrors(err))
	}

	// Create the app.
	app, err := services.CreateApp(request.Name)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err)
	}

	// Return the app.
	response := responses.App{}
	response.SetApp(app)

	return c.JSON(response)
}
