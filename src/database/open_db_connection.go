package database

import (
	"api-auth/main/src/models"
	"context"
	"errors"
	"fmt"
	"time"

	utilsdb "github.com/ArnoldPMolenaar/api-utils/database"
	"gorm.io/gorm"
)

var Pg *gorm.DB

// OpenDBConnection Start a new database connection.
// Also tries to migrate the database schema.
func OpenDBConnection() error {
	// Open connection to database.
	db, err := utilsdb.PostgresSQLConnection()
	if err != nil {
		return err
	}

	// Migrate the database schema.
	err = Migrate(db)
	if err != nil {
		return err
	}

	// Set the global DB variable.
	Pg = db

	return nil
}

// ReadinessCheck verifies that the database connection is initialized and reachable.
func ReadinessCheck() error {
	if Pg == nil {
		return errors.New("database connection is not initialized")
	}

	sqlDB, err := Pg.DB()
	if err != nil {
		return fmt.Errorf("database sql handle unavailable: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	return nil
}

// MigrationReadinessCheck verifies that required tables and seed data exist.
func MigrationReadinessCheck() error {
	if Pg == nil {
		return errors.New("database connection is not initialized")
	}

	requiredTables := []any{
		&models.App{},
		&models.Permission{},
		&models.Recipe{},
		&models.Role{},
		&models.User{},
		&models.UserAppActivity{},
		&models.UserAppRecipe{},
		&models.UserAppRefreshToken{},
		&models.UserAppRolePermission{},
	}
	for _, table := range requiredTables {
		if !Pg.Migrator().HasTable(table) {
			return fmt.Errorf("missing required table for %T", table)
		}
	}

	type seedCheck struct {
		model any
		name  string
		items []string
	}

	seedChecks := []seedCheck{
		{model: &models.Recipe{}, name: "recipe", items: []string{"UsernamePassword"}},
		{model: &models.Permission{}, name: "permission", items: []string{"Read", "Create", "Update", "Delete"}},
		{model: &models.Role{}, name: "role", items: []string{"SuperAdmin", "Blocked"}},
	}

	for _, check := range seedChecks {
		var count int64
		if err := Pg.Model(check.model).Where("name IN ?", check.items).Count(&count).Error; err != nil {
			return fmt.Errorf("failed to validate %s seeds: %w", check.name, err)
		}

		if count < int64(len(check.items)) {
			return fmt.Errorf("%s seeds incomplete: have %d, want %d", check.name, count, len(check.items))
		}
	}

	return nil

}
