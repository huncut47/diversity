package models

type User struct {
	UserID   int    `gorm:"column:user_id;primaryKey;autoIncrement"`
	Username string `gorm:"column:username"`
	Email    string `gorm:"column:email"`
	PwHash   string `gorm:"column:pw_hash"`
}

func (User) TableName() string { return "user" }