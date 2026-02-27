package models

type Message struct {
	MessageId int    `json:"message_id"`
	AuthorId  int    `json:"author_id"`
	Text      string `json:"content"`
	PubDate   int    `json:"pub_date"`
	Flagged   int    `json:"flagged"`
	Username  string `json:"user"`
	Email     string `json:"email"`
}
