package models

type Role struct {
	Name string `gorm:"primaryKey:true;not null;autoIncrement:false"`

	// Relationships.
	Permissions []Permission `gorm:"many2many:role_permissions"`
}
