package models

import (
	"database/sql"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username        string  `gorm:"not null;uniqueIndex:uni_username_app_name"`
	Email           string  `gorm:"not null;uniqueIndex:uni_email_app_name"`
	PhoneNumber     *string `gorm:"null;uniqueIndex:uni_phone_app_name"`
	AppName         string  `gorm:"not null;uniqueIndex:uni_username_app_name;uniqueIndex:uni_email_app_name;uniqueIndex:uni_phone_app_name"`
	Password        string  `gorm:"not null"`
	EmailVerifiedAt sql.NullTime
	PhoneVerifiedAt sql.NullTime
	IsTempPassword  bool `gorm:"not null;default:false"`

	// Relationships.
	App              App `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:AppName;references:Name"`
	AppRecipes       []UserAppRecipe
	AppRefreshTokens []UserAppRefreshToken
	AppRoles         []UserAppRolePermission
	AppActivity      []UserAppActivity
}
