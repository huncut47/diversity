package web

import (
	"database/sql"
	"log"
	"minitwit/internal/models"
	"net/http"
	"time"
)

func (app *App) getUserByUsername(username string) (*models.User, error) {
	var u models.User

	err := app.DB.
		QueryRow(`SELECT user_id, username, email, pw_hash FROM "user" WHERE username = ?`, username).
		Scan(&u.UserID, &u.Username, &u.Email, &u.PwHash)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func scanMessages(rows *sql.Rows) ([]models.Message, error) {
	var messages []models.Message
	for rows.Next() {
		var m models.Message
		err := rows.Scan(&m.MessageId, &m.AuthorId, &m.Text, &m.PubDate, &m.Flagged, &m.Username, &m.Email)
		if err != nil {
			return nil, err
		}
		messages = append(messages, m)
	}
	return messages, rows.Err()
}

func (app *App) getPublicMessages(limit int) ([]models.Message, error) {
	rows, err := app.DB.Query(`
		select message.message_id, message.author_id, message.text,
			message.pub_date, message.flagged, user.username, user.email
		from message, user
		where message.flagged = 0 and message.author_id = user.user_id
		order by message.pub_date desc limit ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMessages(rows)
}

func (app *App) getTimelineMessages(userID int, limit int) ([]models.Message, error) {
	rows, err := app.DB.Query(`
		select message.message_id, message.author_id, message.text,
			message.pub_date, message.flagged, user.username, user.email
		from message, user
		where message.flagged = 0 and message.author_id = user.user_id and (
			user.user_id = ? or
			user.user_id in (select whom_id from follower where who_id = ?))
		order by message.pub_date desc limit ?`, userID, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMessages(rows)
}

func (app *App) getUserMessages(userID int, limit int) ([]models.Message, error) {
	rows, err := app.DB.Query(`
		select message.message_id, message.author_id, message.text, message.pub_date, message.flagged,
			user.username, user.email
		from message, user
		where user.user_id = message.author_id and user.user_id = ?
		order by message.pub_date desc limit ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMessages(rows)
}
func (app *App) getSessionUserID(r *http.Request) int {
	session, _ := app.Store.Get(r, "session")

	log.Printf("getSessionUserID: session.Values = %#v", session.Values)

	userID, ok := session.Values["user_id"].(int)
	if !ok {
		return 0
	}
	return userID
}

func (app *App) getUserId(username string) (int, error) {
	var id int
	err := app.DB.QueryRow("select user_id from user where username = ?", username).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}

func (app *App) followUser(followerID int, followedID int) error {
	_, err := app.DB.Exec(`insert into follower (who_id, whom_id) values (?, ?)`, followerID, followedID)
	return err
}

func (app *App) unfollowUser(followerID int, followedID int) error {
	_, err := app.DB.Exec(`delete from follower where who_id = ? and whom_id = ?`, followerID, followedID)
	return err
}

func (app *App) isFollowing(followerID int, followedID int) (bool, error) {
	var count int
	err := app.DB.
		QueryRow(`select count(*) from follower where who_id = ? and whom_id = ?`, followerID, followedID).
		Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (app *App) getUserById(userID int) (*models.User, error) {
	var u models.User

	err := app.DB.
		QueryRow(`SELECT user_id, username, email, pw_hash FROM "user" WHERE user_id = ?`, userID).
		Scan(&u.UserID, &u.Username, &u.Email, &u.PwHash)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &u, nil
}

func (app *App) addUser(username string, email string, pwHash string) error {
	_, err := app.DB.Exec(`insert into user (
                username, email, pw_hash) values (?, ?, ?)`, username, email, pwHash)
	return err
}

func (app *App) insertMessage(authorID int, text string) error {
	_, err := app.DB.Exec(`insert into message (author_id, text, pub_date, flagged)
            values (?, ?, ?, 0)`, authorID, text, time.Now().Unix())
	return err
}

func (app *App) getLatestMessages(limit int, userID *int) ([]models.Message, error) {
	if userID == nil {
		rows, err := app.DB.Query(`select *
		from message
		where flagged = 0
		order by pubdate desc
		limit ?`, limit)

		if err != nil {
			return nil, err
		}
		defer rows.Close()

		return scanMessages(rows)
	} else {
		rows, err := app.DB.Query(`select *
		from message
		where flagged = 0 and userID = ?
		order by pubdate desc
		limit ?`, userID, limit)

		if err != nil {
			return nil, err
		}
		defer rows.Close()

		return scanMessages(rows)
	}

}

func (app *App) getUserFollowing(userID int, limit int) ([]string, error) {
	rows, err := app.DB.Query(`select user.username
		from follower, user
		where follower.who_id = ? and follower.whom_id = user.user_id limit ?`, userID, limit)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var following []string
	for rows.Next() {
		var username string
		err := rows.Scan(&username)
		if err != nil {
			return nil, err
		}
		following = append(following, username)
	}
	return following, rows.Err()
}
