package models

import "time"

type UserAppRefreshToken struct {
	UserID     uint      `gorm:"primaryKey:true;not null;autoIncrement:false"`
	AppName    string    `gorm:"primaryKey:true;not null;autoIncrement:false"`
	Token      string    `gorm:"not null"`
	ValidUntil time.Time `gorm:"not null"`

	// Relationships.
	User User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:UserID;references:ID"`
	App  App  `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:AppName;references:Name"`
}
