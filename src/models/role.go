package models

type Role struct {
	Name string `gorm:"primaryKey:true;not null;autoIncrement:false"`
}
