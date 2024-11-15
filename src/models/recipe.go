package models

type Recipe struct {
	Name string `gorm:"primaryKey:true;not null;autoIncrement:false"`
}
