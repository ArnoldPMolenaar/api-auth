package services

import (
	"api-auth/main/src/database"
	"api-auth/main/src/dto/requests"
	"api-auth/main/src/dto/responses"
	"api-auth/main/src/enums"
	"api-auth/main/src/models"
	"database/sql"
	"github.com/google/uuid"
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
func IsRefreshTokenValid(userID uint, app, refreshToken string) (bool, error) {
	var count int64

	if result := database.Pg.Model(&models.UserAppRefreshToken{}).
		Where("user_id = ? AND app_name = ? AND token = ? AND valid_until > ?", userID, app, refreshToken, time.Now().UTC()).
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
			AppName:    signUp.App,
			RecipeName: recipe,
		})
	}

	// Bind the user roles.
	for _, role := range signUp.Roles {
		user.AppRoles = append(user.AppRoles, models.UserAppRole{
			AppName:  signUp.App,
			RoleName: role,
		})
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
		Preload("AppRoles.Role.Permissions").
		Find(&user, "username = ?", username); result.Error != nil {
		return user, result.Error
	}

	return user, nil
}

// GetUserByID method to get a user by ID.
func GetUserByID(userID uint) (models.User, error) {
	var user models.User

	if result := database.Pg.Preload("AppRoles").
		Preload("AppRoles.Role.Permissions").
		Find(&user, "id = ?", userID); result.Error != nil {
		return user, result.Error
	}

	return user, nil
}

// RotateRefreshToken method to rotate a refresh token.
// It Inserts or Updates the refresh token and returns the new token.
func RotateRefreshToken(app string, userID uint) (*models.UserAppRefreshToken, error) {
	refreshToken := &models.UserAppRefreshToken{
		UserID:     userID,
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

// DeleteRefreshToken method to delete a refresh token.
func DeleteRefreshToken(app string, userID uint) error {
	if result := database.Pg.Delete(&models.UserAppRefreshToken{}, "app_name = ? AND user_id = ?", app, userID); result.Error != nil {
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
		if err := TokenDeleteFromCache(apps[i], userID); err != nil {
			return err
		}
	}

	// Delete all refresh tokens.
	if result := database.Pg.Delete(&models.UserAppRefreshToken{}, "user_id = ?", userID); result.Error != nil {
		return result.Error
	}

	return nil
}
