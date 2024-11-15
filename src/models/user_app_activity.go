package models

import "time"

type UserAppActivity struct {
	UserID               uint   `gorm:"primaryKey:true;not null;autoIncrement:false"`
	AppName              string `gorm:"primaryKey:true;not null;autoIncrement:false"`
	LastLoginAt          time.Time
	LastPasswordChangeAt time.Time

	// Relationships.
	User User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:UserID;references:ID" json:"-"`
	App  App  `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:AppName;references:Name" json:"-"`
}
