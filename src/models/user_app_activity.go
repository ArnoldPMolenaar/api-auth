package models

import (
	"database/sql"
)

type UserAppActivity struct {
	UserID      uint   `gorm:"primaryKey:true;not null;autoIncrement:false"`
	AppName     string `gorm:"primaryKey:true;not null;autoIncrement:false"`
	LastLoginAt sql.NullTime

	// Relationships.
	User User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:UserID;references:ID"`
	App  App  `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:AppName;references:Name"`
}
