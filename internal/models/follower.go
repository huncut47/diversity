package models

type Follower struct {
	WhoId  int `gorm:"column:who_id;primaryKey"`
	WhomId int `gorm:"column:whom_id;primaryKey"`
}

func (Follower) TableName() string { return "follower" }