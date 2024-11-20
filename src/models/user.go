package models

import (
	"database/sql"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username        string  `gorm:"not null;unique"`
	Email           string  `gorm:"not null;unique"`
	PhoneNumber     *string `gorm:"null;unique"`
	Password        string  `gorm:"not null"`
	EmailVerifiedAt sql.NullTime
	PhoneVerifiedAt sql.NullTime
	IsTempPassword  bool `gorm:"not null;default:false"`

	// Relationships.
	AppRecipes       []UserAppRecipe
	AppRefreshTokens []UserAppRefreshToken
	AppRoles         []UserAppRole
	AppActivity      []UserAppActivity
}
