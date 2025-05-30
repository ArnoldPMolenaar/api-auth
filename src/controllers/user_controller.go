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
	"maps"
	"slices"
	"strings"
)

// GetUserRecipesByUsername method to get user recipes by username.
func GetUserRecipesByUsername(c *fiber.Ctx) error {
	values := c.Request().URI().QueryArgs()
	app := string(values.Peek("app"))
	username := string(values.Peek("username"))

	// Check if user exists.
	if active, err := services.IsUserActive(username); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if !active {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.UsernameEmailUnknown, "Username and Email is unknown.")
	}

	// Check if app exists.
	if available, err := services.IsAppAvailable(app); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.AppExists, "AppName does not exist.")
	}

	// Get user recipes.
	if recipes, err := services.GetUserRecipesByUsername(app, username); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else {
		return c.JSON(recipes)
	}
}

// GetUser method to get user by ID.
func GetUser(c *fiber.Ctx) error {
	// Get the userID parameter from the URL.
	userIDParam := c.Params("id")
	if userIDParam == "" {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.MissingRequiredParam, "User ID is required.")
	}
	userID, err := util.StringToUint(userIDParam)
	if err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.InvalidParam, "Invalid User ID.")
	}

	// Get apps from claims.
	claim := c.Locals("claims")
	if claim == nil {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Claims not found.")
	}
	accessClaims, ok := claim.(*claims.AccessClaims)
	if !ok {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Invalid claims type.")
	}
	appNames := make([]string, len(accessClaims.Apps))
	for index, name := range slices.Collect(maps.Keys(accessClaims.Apps)) {
		appNames[index] = utils.CamelcaseToPascalCase(name)
	}

	// Get the user.
	user, err := services.GetUserByID(userID)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// If apps are provided, check if the user has any of the apps.
	var hasApp bool
outer:
	for _, appName := range appNames {
		for _, app := range user.AppRecipes {
			if app.AppName == appName {
				hasApp = true
				break outer
			}
		}
	}
	if !hasApp {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User does not have the specified app.")
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
		"app_name":     true,
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
	dbResult := database.Pg.Unscoped().Scopes(queryFunc, sortFunc).
		Joins("JOIN user_app_recipes ON user_id = id").
		Limit(limit).
		Offset(offset)

	total := int64(0)
	dbCount := database.Pg.Unscoped().Scopes(queryFunc).
		Model(&models.User{}).
		Joins("JOIN user_app_recipes ON user_id = id")

	// Get apps from claims.
	if !strings.Contains(values.String(), "app_name") {
		claim := c.Locals("claims")
		if claim == nil {
			return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Claims not found.")
		}
		accessClaims, ok := claim.(*claims.AccessClaims)
		if !ok {
			return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Invalid claims type.")
		}
		appNames := make([]string, len(accessClaims.Apps))
		for index, name := range slices.Collect(maps.Keys(accessClaims.Apps)) {
			appNames[index] = utils.CamelcaseToPascalCase(name)
		}

		dbResult = dbResult.Where("app_name IN ?", appNames)
		dbCount = dbCount.Where("app_name IN ?", appNames)
	}

	if dbResult.Find(&users).Error != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, dbResult.Error.Error())
	}

	dbCount.Count(&total)
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

// GetUsersLookup method to get users lookup by apps.
func GetUsersLookup(c *fiber.Ctx) error {
	apps := &requests.Apps{}
	if err := c.QueryParser(apps); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.BodyParse, err.Error())
	}

	// Get apps from claims.
	claim := c.Locals("claims")
	if claim == nil {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Claims not found.")
	}
	accessClaims, ok := claim.(*claims.AccessClaims)
	if !ok {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Invalid claims type.")
	}
	appNames := slices.Collect(maps.Keys(accessClaims.Apps))

	if len(apps.Names) == 0 {
		apps.Names = make([]string, len(accessClaims.Apps))
		for index, name := range appNames {
			apps.Names[index] = utils.CamelcaseToPascalCase(name)
		}
	} else {
		for _, appName := range apps.Names {
			if !slices.Contains(appNames, util.PascalCaseToCamelcase(appName)) {
				return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "User does not have the specified app.")
			}
		}
	}

	usersLookup, err := services.GetUsersLookup(apps.Names)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	}

	response := make([]responses.UserLookup, len(usersLookup))
	for i := range usersLookup {
		response[i] = responses.UserLookup{}
		response[i].ToUserLookup(&usersLookup[i])
	}

	return c.JSON(response)
}

// IsUsernameAvailable method to check if username is available.
func IsUsernameAvailable(c *fiber.Ctx) error {
	username := string(c.Request().URI().QueryArgs().Peek("username"))
	if username == "" {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.MissingRequiredParam, "Username is required.")
	}

	if available, err := services.IsUsernameAvailable(username); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else {
		response := responses.Available{}
		response.SetAvailable(available)

		return c.JSON(response)
	}
}

// IsEmailAvailable method to check if email is available.
func IsEmailAvailable(c *fiber.Ctx) error {
	email := string(c.Request().URI().QueryArgs().Peek("email"))
	if email == "" {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.MissingRequiredParam, "Email is required.")
	}

	if available, err := services.IsEmailAvailable(email); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else {
		response := responses.Available{}
		response.SetAvailable(available)

		return c.JSON(response)
	}
}

// IsPhoneNumberAvailable method to check if phone number is available.
func IsPhoneNumberAvailable(c *fiber.Ctx) error {
	phoneNumber := string(c.Request().URI().QueryArgs().Peek("phoneNumber"))
	if phoneNumber == "" {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.MissingRequiredParam, "Phone number is required.")
	}

	if available, err := services.IsPhoneNumberAvailable(&phoneNumber); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else {
		response := responses.Available{}
		response.SetAvailable(available)

		return c.JSON(response)
	}
}

// CreateUser method to create a new user.
func CreateUser(c *fiber.Ctx) error {
	// Create a new user auth struct.
	createUser := &requests.CreateUser{}

	// Check, if received JSON data is parsed.
	if err := c.BodyParser(createUser); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.BodyParse, err.Error())
	}

	// Validate user fields.
	validate := util.NewValidator()
	if err := validate.Struct(createUser); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.Validator, util.ValidatorErrors(err))
	}

	// Check if user already exists.
	if available, err := services.IsUsernameAvailable(createUser.Username); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.UsernameExists, "Username already exists.")
	}

	if available, err := services.IsEmailAvailable(createUser.Email); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.EmailExists, "Email already exists.")
	}

	if createUser.PhoneNumber != nil {
		if available, err := services.IsPhoneNumberAvailable(createUser.PhoneNumber); err != nil {
			return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
		} else if !available {
			return errorutil.Response(c, fiber.StatusBadRequest, errors.PhoneNumberExists, "Phone already exists.")
		}
	}

	// Check if roles are valid.
	for i := range createUser.Roles {
		if len(createUser.Roles[i].Permissions) == 0 {
			return errorutil.Response(c, fiber.StatusBadRequest, errors.PermissionsEmpty, "Empty permissions in role is not allowed.")
		}
	}

	// Get apps from claims.
	claim := c.Locals("claims")
	if claim == nil {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Claims not found.")
	}
	accessClaims, ok := claim.(*claims.AccessClaims)
	if !ok {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Invalid claims type.")
	}
	appNames := make([]string, len(accessClaims.Apps))
	for index, name := range slices.Collect(maps.Keys(accessClaims.Apps)) {
		appNames[index] = utils.CamelcaseToPascalCase(name)
	}

	// If apps are provided, check if the user has all the apps.
	hasApp := true
	for i := range createUser.Recipes {
		if !slices.Contains(appNames, createUser.Recipes[i].App) {
			hasApp = false
			break
		}
	}
	for i := range createUser.Roles {
		if !slices.Contains(appNames, createUser.Roles[i].App) {
			hasApp = false
			break
		}
	}
	if !hasApp {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "User does not have the specified app.")
	}

	// Create a new user.
	if user, err := services.CreateUser(createUser); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else {
		return c.JSON(user)
	}
}

// UpdateUser method to update user by ID.
func UpdateUser(c *fiber.Ctx) error {
	// Get the userID parameter from the URL.
	userIDParam := c.Params("id")
	if userIDParam == "" {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.MissingRequiredParam, "User ID is required.")
	}
	userID, err := util.StringToUint(userIDParam)
	if err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.InvalidParam, "Invalid User ID.")
	}

	// Get apps from claims.
	claim := c.Locals("claims")
	if claim == nil {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Claims not found.")
	}
	accessClaims, ok := claim.(*claims.AccessClaims)
	if !ok {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Invalid claims type.")
	}
	appNames := make([]string, len(accessClaims.Apps))
	for index, name := range slices.Collect(maps.Keys(accessClaims.Apps)) {
		appNames[index] = utils.CamelcaseToPascalCase(name)
	}

	// Get the request body.
	requestUser := &requests.UpdateUser{}
	if err := c.BodyParser(requestUser); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.BodyParse, "Invalid request body.")
	}

	// Validate user fields.
	validate := util.NewValidator()
	if err := validate.Struct(requestUser); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.Validator, util.ValidatorErrors(err))
	}

	// Check if roles are valid.
	for i := range requestUser.Roles {
		if len(requestUser.Roles[i].Permissions) == 0 {
			return errorutil.Response(c, fiber.StatusBadRequest, errors.PermissionsEmpty, "Empty permissions in role is not allowed.")
		}
	}

	// Get the user.
	user, err := services.GetUserByID(userID)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// If apps are provided, check if the user has any of the apps.
	var hasApp bool
outer:
	for _, appName := range appNames {
		for _, app := range user.AppRecipes {
			if app.AppName == appName {
				hasApp = true
				break outer
			}
		}
	}
	if !hasApp {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User does not have the specified app.")
	}

	// Check if user already exists.
	if requestUser.Username != user.Username {
		if available, err := services.IsUsernameAvailable(requestUser.Username); err != nil {
			return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
		} else if !available {
			return errorutil.Response(c, fiber.StatusBadRequest, errors.UsernameExists, "Username already exists.")
		}
	}

	if requestUser.Email != user.Email {
		if available, err := services.IsEmailAvailable(requestUser.Email); err != nil {
			return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
		} else if !available {
			return errorutil.Response(c, fiber.StatusBadRequest, errors.EmailExists, "Email already exists.")
		}
	}

	if requestUser.PhoneNumber != nil && (user.PhoneNumber == nil || *requestUser.PhoneNumber != *user.PhoneNumber) {
		if available, err := services.IsPhoneNumberAvailable(requestUser.PhoneNumber); err != nil {
			return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
		} else if !available {
			return errorutil.Response(c, fiber.StatusBadRequest, errors.PhoneNumberExists, "Phone already exists.")
		}
	}

	// Check if the user data has been modified since it was last fetched.
	if requestUser.UpdatedAt.Unix() < user.UpdatedAt.Unix() {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.OutOfSync, "Data is out of sync.")
	}

	// Update the user.
	updatedUser, err := services.UpdateUser(&user, requestUser, appNames)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	}

	// Return the user.
	response := responses.User{}
	response.SetUser(updatedUser)

	return c.JSON(response)
}

// UpdateUserPassword method to update user password by ID.
func UpdateUserPassword(c *fiber.Ctx) error {
	// Get the userID parameter from the URL.
	userIDParam := c.Params("id")
	if userIDParam == "" {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.MissingRequiredParam, "User ID is required.")
	}
	userID, err := util.StringToUint(userIDParam)
	if err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.InvalidParam, "Invalid User ID.")
	}

	// Get the request body.
	requestPassword := &requests.UpdateUserPassword{}
	if err := c.BodyParser(requestPassword); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.BodyParse, "Invalid request body.")
	}

	// Validate password fields.
	validate := util.NewValidator()
	if err := validate.Struct(requestPassword); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.Validator, util.ValidatorErrors(err))
	}

	// Check if app exists.
	if available, err := services.IsAppAvailable(requestPassword.App); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.AppExists, "AppName does not exist.")
	}

	// Get the user.
	user, err := services.GetUserByID(userID)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// Check if the old password is correct.
	if valid, err := services.IsPasswordCorrect(user.Username, requestPassword.OldPassword); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if !valid {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.InvalidPassword, "Invalid password.")
	}

	// Update the user password.
	if err := services.UpdateUserPassword(user.ID, requestPassword.App, requestPassword.NewPassword); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
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
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.BodyParse, "Invalid request body.")
	}

	// Validate password fields.
	validate := util.NewValidator()
	if err := validate.Struct(requestPassword); err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.Validator, util.ValidatorErrors(err))
	}

	// Check if app exists.
	if available, err := services.IsAppAvailable(requestPassword.App); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if !available {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.AppExists, "AppName does not exist.")
	}

	// Get the user.
	user, err := services.GetUserByID(uint(passwordClaims.Id))
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// Update the user password.
	if err := services.UpdateUserPassword(user.ID, requestPassword.App, requestPassword.Password); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	}

	// Delete the reset token from the cache.
	if err := services.TokenDeleteAllFromCache(requestPassword.App, uint(passwordClaims.Id), passwordClaims.Type); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.CacheError, err.Error())
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
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// Update the user email.
	if err := services.UpdateUserEmailVerification(user.ID, emailClaims.Email); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	}

	// Delete the verification token from the cache.
	if err := services.TokenDeleteAllFromCache(emailClaims.App, user.ID, enums.EmailVerification); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.CacheError, err.Error())
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// RestoreUser method to restore user by ID.
func RestoreUser(c *fiber.Ctx) error {
	// Get the userID parameter from the URL.
	userIDParam := c.Params("id")
	if userIDParam == "" {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.MissingRequiredParam, "User ID is required.")
	}
	userID, err := util.StringToUint(userIDParam)
	if err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.InvalidParam, "Invalid User ID.")
	}

	// Get apps from claims.
	claim := c.Locals("claims")
	if claim == nil {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Claims not found.")
	}
	accessClaims, ok := claim.(*claims.AccessClaims)
	if !ok {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Invalid claims type.")
	}
	appNames := make([]string, len(accessClaims.Apps))
	for index, name := range slices.Collect(maps.Keys(accessClaims.Apps)) {
		appNames[index] = utils.CamelcaseToPascalCase(name)
	}

	// Get the user.
	user, err := services.GetUserByID(userID, true)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// If apps are provided, check if the user has all the apps.
	hasApp := true
	for i := range user.AppRecipes {
		if !slices.Contains(appNames, user.AppRecipes[i].AppName) {
			hasApp = false
			break
		}
	}
	for i := range user.AppRoles {
		if !slices.Contains(appNames, user.AppRoles[i].AppName) {
			hasApp = false
			break
		}
	}
	if !hasApp {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "User does not have the specified app.")
	}

	// Restore the user.
	if err := services.RestoreUser(user.ID); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// DeleteUser method to delete user by ID.
func DeleteUser(c *fiber.Ctx) error {
	// Get the userID parameter from the URL.
	userIDParam := c.Params("id")
	if userIDParam == "" {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.MissingRequiredParam, "User ID is required.")
	}
	userID, err := util.StringToUint(userIDParam)
	if err != nil {
		return errorutil.Response(c, fiber.StatusBadRequest, errorutil.InvalidParam, "Invalid User ID.")
	}

	// Get userID from claims.
	claim := c.Locals("claims")
	if claim == nil {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Claims not found.")
	}

	accessClaims, ok := claim.(*claims.AccessClaims)
	if !ok {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Invalid claims type.")
	}

	// Get apps from claims.
	appNames := make([]string, len(accessClaims.Apps))
	for index, name := range slices.Collect(maps.Keys(accessClaims.Apps)) {
		appNames[index] = utils.CamelcaseToPascalCase(name)
	}

	// Check if the userID is not the same as the logged-in user.
	if int(userID) == accessClaims.Id {
		return errorutil.Response(c, fiber.StatusBadRequest, errors.NoSelfDelete, "It is not possible to delete yourself")
	}

	// Get the user.
	user, err := services.GetUserByID(userID)
	if err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	} else if user.ID == 0 {
		return errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	// If apps are provided, check if the user has all the apps.
	hasApp := true
	for i := range user.AppRecipes {
		if !slices.Contains(appNames, user.AppRecipes[i].AppName) {
			hasApp = false
			break
		}
	}
	for i := range user.AppRoles {
		if !slices.Contains(appNames, user.AppRoles[i].AppName) {
			hasApp = false
			break
		}
	}
	if !hasApp {
		return errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "User does not have the specified app.")
	}

	// Delete the user.
	if err := services.DeleteUser(user.ID); err != nil {
		return errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	}

	return c.SendStatus(fiber.StatusNoContent)
}
