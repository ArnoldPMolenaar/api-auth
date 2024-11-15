package models

import (
	"gorm.io/gorm"
	"time"
)

type User struct {
	gorm.Model
	Username        string    `gorm:"not null;unique"`
	Email           string    `gorm:"not null;unique"`
	PhoneNumber     string    `gorm:"not null;unique"`
	Password        string    `gorm:"not null"`
	EmailVerifiedAt time.Time `gorm:"null"`
	PhoneVerifiedAt time.Time `gorm:"null"`
	IsTempPassword  bool      `gorm:"not null;default:false"`

	// Relationships.
	AppRecipes       []UserAppRecipe
	AppRefreshTokens []UserAppRefreshToken
	AppRoles         []UserAppRole
	AppActivity      []UserAppActivity
}
