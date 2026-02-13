package models

type Message struct {
	MessageId int
	AuthorId  int
	Text      string
	PubDate   int
	Flagged   int
	Username  string
	Email     string
}
