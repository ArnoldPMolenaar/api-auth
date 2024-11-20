package services

import (
	"api-auth/main/src/database"
	"api-auth/main/src/dto/requests"
	"api-auth/main/src/dto/responses"
	"api-auth/main/src/models"
	"errors"
)

// IsUsernameAvailable method to check if a username is available.
func IsUsernameAvailable(username string) (bool, error) {
	if username == "" {
		return false, errors.New("username is required")
	}

	if result := database.Pg.Limit(1).Find(&models.User{}, "username = ?", username); result.Error != nil {
		return false, result.Error
	} else {
		return result.RowsAffected == 0, nil
	}
}

// IsEmailAvailable method to check if an email is available.
func IsEmailAvailable(email string) (bool, error) {
	if email == "" {
		return false, errors.New("email is required")
	}

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

// Signup method to create a new user.
func Signup(signUp *requests.Signup) (responses.Signup, error) {
	var err error
	var isTempPassword bool
	var response responses.Signup

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

	response.SetSignup(user)

	return response, nil
}
