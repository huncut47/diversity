package models

type Message struct {
	MessageId int    `gorm:"column:message_id;primaryKey;autoIncrement" json:"message_id"`
	AuthorId  int    `gorm:"column:author_id"                           json:"author_id"`
	Text      string `gorm:"column:text"                                json:"content"`
	PubDate   int    `gorm:"column:pub_date"                            json:"pub_date"`
	Flagged   int    `gorm:"column:flagged"                             json:"flagged"`
	Username  string `gorm:"-:migration;<-:false;column:username"        json:"user"`
	Email     string `gorm:"-:migration;<-:false;column:email"           json:"email"`
}

func (Message) TableName() string { return "message" }