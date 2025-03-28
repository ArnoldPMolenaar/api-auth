package models

type UserAppRole struct {
	UserID   uint   `gorm:"primaryKey:true;not null;autoIncrement:false"`
	AppName  string `gorm:"primaryKey:true;not null;autoIncrement:false"`
	RoleName string `gorm:"primaryKey:true;not null;autoIncrement:false"`

	// Relationships.
	User User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:UserID;references:ID"`
	App  App  `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:AppName;references:Name"`
	Role Role `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:RoleName;references:Name"`
}
