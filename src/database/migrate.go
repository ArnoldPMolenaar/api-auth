package database

import (
	"api-auth/main/src/models"
	"gorm.io/gorm"
)

// Migrate the database schema.
// See: https://gorm.io/docs/migration.html#Auto-Migration
func Migrate(db *gorm.DB) error {
	err := db.AutoMigrate(
		&models.App{},
		&models.Permission{},
		&models.Recipe{},
		&models.Role{},
		&models.User{},
		&models.UserAppActivity{},
		&models.UserAppRecipe{},
		&models.UserAppRefreshToken{},
		&models.UserAppRole{})
	if err != nil {
		return err
	}

	// Seed Recipe
	recipes := []string{"UsernamePassword"}
	for _, recipe := range recipes {
		if err := db.FirstOrCreate(&models.Recipe{}, models.Recipe{Name: recipe}).Error; err != nil {
			return err
		}
	}

	// Seed Permission
	permissions := []string{"Create", "Update", "Delete"}
	for _, permission := range permissions {
		if err := db.FirstOrCreate(&models.Permission{}, models.Permission{Name: permission}).Error; err != nil {
			return err
		}
	}

	// Seed Role
	roles := []string{"SuperAdmin", "Blocked"}
	for _, role := range roles {
		r := models.Role{Name: role}
		if err := db.FirstOrCreate(&models.Role{}, r).Error; err != nil {
			return err
		}

		var allPermissions []models.Permission
		if err := db.Find(&allPermissions).Error; err != nil {
			return err
		}

		if err := db.Model(&r).Association("Permissions").Replace(allPermissions); err != nil {
			return err
		}
	}

	return nil
}
