package services

import (
	"api-auth/main/src/database"
	"api-auth/main/src/dto/requests"
	"api-auth/main/src/dto/responses"
	"api-auth/main/src/enums"
	"api-auth/main/src/models"
	"database/sql"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"slices"
	"time"
)

// IsUsernameAvailable method to check if a username is available.
func IsUsernameAvailable(username string) (bool, error) {
	if result := database.Pg.Limit(1).Find(&models.User{}, "username = ?", username); result.Error != nil {
		return false, result.Error
	} else {
		return result.RowsAffected == 0, nil
	}
}

// IsEmailAvailable method to check if an email is available.
func IsEmailAvailable(email string) (bool, error) {
	if result := database.Pg.Limit(1).Find(&models.User{}, "email = ?", email); result.Error != nil {
		return false, result.Error
	} else {
		return result.RowsAffected == 0, nil
	}
}

// IsEmailVerified method to check if an email is verified.
func IsEmailVerified(email string) (bool, error) {
	if result := database.Pg.Limit(1).Find(&models.User{}, "email = ? AND email_verified_at IS NOT NULL", email); result.Error != nil {
		return false, result.Error
	} else {
		return result.RowsAffected == 1, nil
	}
}

// IsPhoneNumberAvailable method to check if a phone number is available.
func IsPhoneNumberAvailable(phoneNumber *string) (bool, error) {
	if result := database.Pg.Limit(1).Find(&models.User{}, "phone_number = ?", phoneNumber); result.Error != nil {
		return false, result.Error
	} else {
		return result.RowsAffected == 0, nil
	}
}

// IsUserActive method to check if a user is active.
func IsUserActive(username string) (bool, error) {
	if result := database.Pg.Limit(1).Find(&models.User{}, "username = ? OR email = ?", username, username); result.Error != nil {
		return false, result.Error
	} else {
		return result.RowsAffected == 1, nil
	}
}

// HasUserRecipe method to check if a user has a recipe.
func HasUserRecipe(app, username string, recipe enums.Recipe) (bool, error) {
	var count int64

	if result := database.Pg.Model(&models.User{}).
		Joins("JOIN user_app_recipes ON user_app_recipes.user_id = users.id").
		Where("username = ? AND recipe_name = ? AND app_name = ?", username, recipe, app).
		Count(&count); result.Error != nil {
		return false, result.Error
	}

	return count > 0, nil
}

// IsPasswordCorrect method to validate a password.
func IsPasswordCorrect(username, password string) (bool, error) {
	var passwordHash string

	// Get the password from the user.
	if result := database.Pg.Model(&models.User{}).
		Select("password").
		Where("username = ? OR email = ?", username, username).
		Find(&passwordHash); result.Error != nil {
		return false, result.Error
	}

	// Compare the password.
	valid := PasswordCompare(password, passwordHash)

	return valid, nil
}

// IsRefreshTokenValid method to check if a refresh token is valid.
func IsRefreshTokenValid(userID uint, deviceID, app, refreshToken string) (bool, error) {
	var count int64

	if result := database.Pg.Model(&models.UserAppRefreshToken{}).
		Where("user_id = ? AND device_id = ? AND app_name = ? AND token = ? AND valid_until > ?", userID, deviceID, app, refreshToken, time.Now().UTC()).
		Count(&count); result.Error != nil {
		return false, result.Error
	}

	return count > 0, nil
}

// IsRefreshTokenUsed method to check if a refresh token is used on that device.
func IsRefreshTokenUsed(userID uint, app, deviceID string) (bool, error) {
	var count int64

	if result := database.Pg.Model(&models.UserAppRefreshToken{}).
		Where("user_id = ? AND app_name = ? AND device_id = ?", userID, app, deviceID).
		Count(&count); result.Error != nil {
		return false, result.Error
	}

	return count > 0, nil
}

// SignUp method to create a new user.
func SignUp(signUp *requests.SignUp) (responses.SignUp, error) {
	var err error
	var isTempPassword bool
	var response responses.SignUp

	// Generate a password if not provided.
	if signUp.Password == "" {
		if signUp.Password, err = PasswordGenerate(16, 4, 0); err != nil {
			return response, err
		}
		isTempPassword = true
	}

	hashedPassword, err := PasswordHash(signUp.Password)
	if err != nil {
		return response, err
	}

	// Bind the default user properties.
	user := models.User{
		Username:       signUp.Username,
		Email:          signUp.Email,
		PhoneNumber:    signUp.PhoneNumber,
		Password:       hashedPassword,
		IsTempPassword: isTempPassword,
	}

	// Bind the user recipes.
	for _, recipe := range signUp.Recipes {
		user.AppRecipes = append(user.AppRecipes, models.UserAppRecipe{
			AppName:    recipe.App,
			RecipeName: recipe.Recipe,
		})
	}

	// Bind the user roles.
	for _, role := range signUp.Roles {
		userAppRolePermission := &models.UserAppRolePermission{
			AppName:  role.App,
			RoleName: role.Role,
		}

		for i := range role.Permissions {
			userAppRolePermission.PermissionName = role.Permissions[i]
			user.AppRoles = append(user.AppRoles, *userAppRolePermission)
		}
	}

	// Create the user.
	if err := database.Pg.Create(&user).Error; err != nil {
		return response, err
	}

	// If the password is temporary, return the password.
	if isTempPassword {
		response.Password = signUp.Password
	}

	response.SetSignUp(&user)

	return response, nil
}

// GetUserRecipesByUsername method to get recipes by username.
func GetUserRecipesByUsername(app, username string) ([]string, error) {
	var recipes []string

	if result := database.Pg.Model(&models.User{}).
		Joins("JOIN user_app_recipes ON user_app_recipes.user_id = users.id").
		Select("user_app_recipes.recipe_name").
		Where("username = ? AND app_name = ?", username, app).
		Find(&recipes); result.Error != nil {
		return nil, result.Error
	}

	return recipes, nil
}

// GetUserByUsername method to get a user by username.
func GetUserByUsername(username string) (models.User, error) {
	var user models.User

	if result := database.Pg.Preload("AppRoles").
		Find(&user, "username = ?", username); result.Error != nil {
		return user, result.Error
	}

	return user, nil
}

// GetUserByEmail method to get a user by email.
func GetUserByEmail(email string) (models.User, error) {
	var user models.User

	if result := database.Pg.Find(&user, "email = ?", email); result.Error != nil {
		return user, result.Error
	}

	return user, nil
}

// GetUserByID method to get a user by ID.
func GetUserByID(userID uint, unscoped ...bool) (models.User, error) {
	var user models.User

	query := database.Pg.Preload("AppRoles").
		Preload("AppRecipes").
		Preload("AppActivity")

	if len(unscoped) > 0 && unscoped[0] {
		query = query.Unscoped()
	}

	if result := query.Find(&user, "id = ?", userID); result.Error != nil {
		return user, result.Error
	}

	return user, nil
}

// RotateRefreshToken method to rotate a refresh token.
// It Inserts or Updates the refresh token and returns the new token.
func RotateRefreshToken(app, deviceID string, userID uint) (*models.UserAppRefreshToken, error) {
	refreshToken := &models.UserAppRefreshToken{
		UserID:     userID,
		DeviceID:   deviceID,
		AppName:    app,
		Token:      uuid.NewString(),
		ValidUntil: TokenRefreshValidUntil(),
	}

	if err := database.Pg.Save(&refreshToken).Error; err != nil {
		return nil, err
	}

	return refreshToken, nil
}

// SetLastLoginAt method to set the last login time of the user.
func SetLastLoginAt(app string, userID uint, lastLoginAt time.Time) error {
	// Convert time.Time to sql.NullTime
	nullLastLoginAt := sql.NullTime{Time: lastLoginAt, Valid: !lastLoginAt.IsZero()}

	activity := models.UserAppActivity{
		UserID:      userID,
		AppName:     app,
		LastLoginAt: nullLastLoginAt,
	}

	if err := database.Pg.Save(&activity).Error; err != nil {
		return err
	}

	return nil
}

// UpdateUser method to update a user.
func UpdateUser(user *models.User, requestUser *requests.UpdateUser, apps []string) (*models.User, error) {
	if requestUser.Email != user.Email {
		user.EmailVerifiedAt = sql.NullTime{}
	}
	if requestUser.PhoneNumber != user.PhoneNumber {
		user.PhoneVerifiedAt = sql.NullTime{}
	}

	user.Username = requestUser.Username
	user.Email = requestUser.Email
	user.PhoneNumber = requestUser.PhoneNumber
	user.UpdatedAt = time.Now().UTC()

	// Create a map of roles and recipes to check for duplicates.
	rolesMap := make(map[string]map[string]map[string]bool)
	recipesMap := make(map[string]map[string]bool)
	for i := range requestUser.Roles {
		if _, ok := rolesMap[requestUser.Roles[i].App]; !ok {
			rolesMap[requestUser.Roles[i].App] = make(map[string]map[string]bool)
		}
		if _, ok := rolesMap[requestUser.Roles[i].App][requestUser.Roles[i].Role]; !ok {
			rolesMap[requestUser.Roles[i].App][requestUser.Roles[i].Role] = make(map[string]bool)
		}
		for j := range requestUser.Roles[i].Permissions {
			rolesMap[requestUser.Roles[i].App][requestUser.Roles[i].Role][requestUser.Roles[i].Permissions[j]] = true
		}
	}
	for i := range requestUser.Recipes {
		if _, ok := recipesMap[requestUser.Recipes[i].App]; !ok {
			recipesMap[requestUser.Recipes[i].App] = make(map[string]bool)
		}
		recipesMap[requestUser.Recipes[i].App][requestUser.Recipes[i].Recipe] = true
	}

	err := database.Pg.Transaction(func(tx *gorm.DB) error {
		// Delete the user roles.
		protectedUserAppRoles := make([]models.UserAppRolePermission, 0, len(user.AppRoles))
		for i := range user.AppRoles {
			if len(apps) > 0 && !slices.Contains(apps, user.AppRoles[i].AppName) {
				protectedUserAppRoles = append(protectedUserAppRoles, user.AppRoles[i])
				continue
			}
			if _, ok := rolesMap[user.AppRoles[i].AppName][user.AppRoles[i].RoleName][user.AppRoles[i].PermissionName]; !ok {
				if result := database.Pg.Delete(&user.AppRoles[i]); result.Error != nil {
					return result.Error
				}
			}
		}
		// Delete the user recipes.
		protectedUserAppRecipes := make([]models.UserAppRecipe, 0, len(user.AppRecipes))
		for i := range user.AppRecipes {
			if len(apps) > 0 && !slices.Contains(apps, user.AppRecipes[i].AppName) {
				protectedUserAppRecipes = append(protectedUserAppRecipes, user.AppRecipes[i])
				continue
			}
			if _, ok := recipesMap[user.AppRecipes[i].AppName][user.AppRecipes[i].RecipeName]; !ok {
				if result := database.Pg.Delete(&user.AppRecipes[i]); result.Error != nil {
					return result.Error
				}
			}
		}

		// Insert the user roles.
		user.AppRoles = protectedUserAppRoles
		for i := range requestUser.Roles {
			if len(apps) > 0 && !slices.Contains(apps, requestUser.Roles[i].App) {
				continue
			}
			userAppRolePermission := models.UserAppRolePermission{
				UserID:   user.ID,
				AppName:  requestUser.Roles[i].App,
				RoleName: requestUser.Roles[i].Role,
			}
			for j := range requestUser.Roles[i].Permissions {
				userAppRolePermission.PermissionName = requestUser.Roles[i].Permissions[j]
				user.AppRoles = append(user.AppRoles, userAppRolePermission)
			}
		}

		// Insert the user recipes.
		user.AppRecipes = protectedUserAppRecipes
		for i := range requestUser.Recipes {
			if len(apps) > 0 && !slices.Contains(apps, requestUser.Recipes[i].App) {
				continue
			}
			user.AppRecipes = append(user.AppRecipes, models.UserAppRecipe{
				UserID:     user.ID,
				AppName:    requestUser.Recipes[i].App,
				RecipeName: requestUser.Recipes[i].Recipe,
			})
		}

		if err := database.Pg.Save(&user).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return user, nil
}

// UpdateUserPassword method to update the user password.
func UpdateUserPassword(userID uint, app, password string) error {
	hashedPassword, err := PasswordHash(password)
	if err != nil {
		return err
	}

	err = database.Pg.Transaction(func(tx *gorm.DB) error {
		if result := database.Pg.Model(&models.User{}).
			Where("id = ?", userID).
			Update("password", hashedPassword).
			Update("is_temp_password", false); result.Error != nil {
			return result.Error
		}

		if result := database.Pg.Model(&models.UserAppActivity{}).
			Where("user_id = ? AND app_name = ?", userID, app).
			Update("last_password_change_at", time.Now().UTC()); result.Error != nil {
			return result.Error
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// UpdateUserEmailVerification method to update the user email.
func UpdateUserEmailVerification(userID uint, email string) error {
	if result := database.Pg.Model(&models.User{}).
		Where("id = ? AND email = ?", userID, email).
		Update("email_verified_at", time.Now().UTC()); result.Error != nil {
		return result.Error
	}

	return nil
}

// RestoreUser function to undo the deleted_at timestamp for a user.
func RestoreUser(userID uint) error {
	// Update the deleted_at field to NULL.
	if err := database.Pg.Model(&models.User{}).Unscoped().Where("id = ?", userID).Update("deleted_at", nil).Error; err != nil {
		return err
	}
	return nil
}

// DeleteRefreshToken method to delete a refresh token.
func DeleteRefreshToken(app, deviceID string, userID uint) error {
	if result := database.Pg.Delete(&models.UserAppRefreshToken{}, "app_name = ? AND device_id = ? AND  user_id = ?", app, deviceID, userID); result.Error != nil {
		return result.Error
	}

	return nil
}

// DestroyUserSessions method to destroy all user sessions.
// This method is needed when a user is using a refresh token that is invalid.
// By destroying all sessions, the user will be forced to sign in again.
func DestroyUserSessions(userID uint) error {
	// Get lists of all refresh tokens.
	apps, err := GetApps()
	if err != nil {
		return err
	}

	// Delete all access tokens from the cache.
	for i := range apps {
		if err := TokenDeleteAllFromCache(apps[i], userID, enums.Access); err != nil {
			return err
		}
	}

	// Delete all refresh tokens.
	if result := database.Pg.Delete(&models.UserAppRefreshToken{}, "user_id = ?", userID); result.Error != nil {
		return result.Error
	}

	return nil
}

// DeleteUser method to delete a user.
func DeleteUser(userID uint) error {
	if result := database.Pg.Delete(&models.User{}, userID); result.Error != nil {
		return result.Error
	}

	if err := DestroyUserSessions(userID); err != nil {
		return err
	}

	return nil
}
