package services

import (
	"api-auth/main/src/database"
	"api-auth/main/src/models"
	"errors"
)

// IsAppAvailable method to check if an app is available.
func IsAppAvailable(app string) (bool, error) {
	if app == "" {
		return false, errors.New("app name is required")
	}

	if result := database.Pg.Limit(1).Find(&models.App{}, "name = ?", app); result.Error != nil {
		return false, result.Error
	} else {
		return result.RowsAffected == 1, nil
	}
}
