package models

type AppState struct {
	Key   string `gorm:"column:key;primaryKey"`
	Value int64  `gorm:"column:value;not null"`
}

func (AppState) TableName() string { return "app_state" }
