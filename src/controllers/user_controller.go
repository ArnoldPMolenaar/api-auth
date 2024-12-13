package controllers

import (
	"api-auth/main/src/claims"
	"api-auth/main/src/database"
	"api-auth/main/src/dto/requests"
	"api-auth/main/src/dto/responses"
	"api-auth/main/src/enums"
	"api-auth/main/src/errors"
	"api-auth/main/src/models"
	"api-auth/main/src/services"
	"api-auth/main/src/utils"
	errorutil "github.com/ArnoldPMolenaar/api-utils/errors"
	"github.com/ArnoldPMolenaar/api-utils/pagination"
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

	// Check if app exists.
	if available, err := services.IsAppAvailable(app); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.AppExists, "AppName does not exist.")
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

// GetUsers function fetches all users from the database.
func GetUsers(c *fiber.Ctx) error {
	users := make([]models.User, 0)
	values := c.Request().URI().QueryArgs()
	allowedColumns := map[string]bool{
		"id":           true,
		"username":     true,
		"email":        true,
		"phone_number": true,
		"created_at":   true,
		"updated_at":   true,
		"deleted_at":   true,
	}

	queryFunc := pagination.Query(values, allowedColumns)
	sortFunc := pagination.Sort(values, allowedColumns)
	page := c.QueryInt("page", 1)
	if page < 1 {
		page = 1
	}
	limit := c.QueryInt("limit", 10)
	if limit < 1 {
		limit = 10
	}
	offset := pagination.Offset(page, limit)

	db := database.Pg.Unscoped().Scopes(queryFunc, sortFunc).Limit(limit).Offset(offset).Find(&users)
	if db.Error != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, db.Error.Error())
	}

	total := int64(0)
	database.Pg.Unscoped().Scopes(queryFunc).Model(&models.User{}).Count(&total)
	pageCount := pagination.Count(int(total), limit)

	paginatedUsers := make([]responses.PaginatedUser, 0)
	for i := range users {
		paginatedUser := responses.PaginatedUser{}
		paginatedUser.SetPaginatedUser(&users[i])
		paginatedUsers = append(paginatedUsers, paginatedUser)
	}

	paginationModel := pagination.CreatePaginationModel(limit, page, pageCount, int(total), paginatedUsers)

	return c.Status(fiber.StatusOK).JSON(paginationModel)
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

func UpdateUserPassword(c *fiber.Ctx) error {
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
	requestPassword := &requests.UpdateUserPassword{}
	if err := c.BodyParser(requestPassword); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.BodyParse, "Invalid request body.")
	}

	// Validate password fields.
	validate := util.NewValidator()
	if err := validate.Struct(requestPassword); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.Validator, util.ValidatorErrors(err))
	}

	// Check if app exists.
	if available, err := services.IsAppAvailable(requestPassword.App); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.AppExists, "AppName does not exist.")
	}

	// Get the user.
	user, err := services.GetUserByID(userID)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// Check if the old password is correct.
	if valid, err := services.IsPasswordCorrect(user.Username, requestPassword.OldPassword); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if !valid {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.InvalidPassword, "Invalid password.")
	}

	// Update the user password.
	if err := services.UpdateUserPassword(user.ID, requestPassword.App, requestPassword.NewPassword); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// UpdateUserPasswordReset method to update user password by reset token.
func UpdateUserPasswordReset(c *fiber.Ctx) error {
	// Get app and userID from claims.
	claim := c.Locals("claims")
	if claim == nil {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Claims not found.")
	}

	passwordClaims, ok := claim.(*claims.PasswordResetClaims)
	if !ok {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Invalid claims type.")
	}

	// Get the request body.
	requestPassword := &requests.UpdateUserPasswordReset{}
	if err := c.BodyParser(requestPassword); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.BodyParse, "Invalid request body.")
	}

	// Validate password fields.
	validate := util.NewValidator()
	if err := validate.Struct(requestPassword); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.Validator, util.ValidatorErrors(err))
	}

	// Check if app exists.
	if available, err := services.IsAppAvailable(requestPassword.App); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.AppExists, "AppName does not exist.")
	}

	// Get the user.
	user, err := services.GetUserByID(uint(passwordClaims.Id))
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// Update the user password.
	if err := services.UpdateUserPassword(user.ID, requestPassword.App, requestPassword.Password); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	}

	// Delete the reset token from the cache.
	if err := services.TokenDeleteFromCache(requestPassword.App, uint(passwordClaims.Id), passwordClaims.Type); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.CacheError, err.Error())
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// UpdateUserEmailVerification method to update user email by verification token.
func UpdateUserEmailVerification(c *fiber.Ctx) error {
	// Get email from claims.
	claim := c.Locals("claims")
	if claim == nil {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Claims not found.")
	}

	emailClaims, ok := claim.(*claims.EmailVerificationClaims)
	if !ok {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Invalid claims type.")
	}

	// Get the user.
	user, err := services.GetUserByID(uint(emailClaims.Id))
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// Update the user email.
	if err := services.UpdateUserEmailVerification(user.ID, emailClaims.Email); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	}

	// Delete the verification token from the cache.
	if err := services.TokenDeleteFromCache(emailClaims.App, user.ID, enums.EmailVerification); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.CacheError, err.Error())
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// RestoreUser method to restore user by ID.
func RestoreUser(c *fiber.Ctx) error {
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
	user, err := services.GetUserByID(userID, true)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// Restore the user.
	if err := services.RestoreUser(user.ID); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errors.QueryError, err.Error())
	}

	return c.SendStatus(fiber.StatusNoContent)
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
