package models

type Permission struct {
	Name string `gorm:"primaryKey:true;not null;autoIncrement:false"`
}
