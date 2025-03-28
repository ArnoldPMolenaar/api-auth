package models

type UserAppRecipe struct {
	UserID     uint   `gorm:"primaryKey:true;not null;autoIncrement:false"`
	AppName    string `gorm:"primaryKey:true;not null;autoIncrement:false"`
	RecipeName string `gorm:"primaryKey:true;not null;autoIncrement:false"`

	// Relationships.
	User   User   `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:UserID;references:ID"`
	App    App    `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:AppName;references:Name"`
	Recipe Recipe `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:RecipeName;references:Name"`
}
