package web

import (
	"log"
	"minitwit/internal/models"
	"net/http"
	"time"
)

 func (app *App) getUserByUsername(username string) (*models.User, error) {
	var user models.User
	result := app.DB.Where("username = ?", username).First(&user)
	if result.Error != nil {
			if result.Error.Error() == "record not found" {
					return nil, nil
			}
			return nil, result.Error
	}
	return &user, nil
}


 func (app *App) getPublicMessages(limit int) ([]models.Message, error) {
	var messages []models.Message
	result := app.DB.
			Select("message.*, user.username, user.email").
			Joins("JOIN user ON user.user_id = message.author_id").
			Where("message.flagged = 0").
			Order("message.pub_date DESC").
			Limit(limit).
			Find(&messages)
	return messages, result.Error
}

func (app *App) getTimelineMessages(userID int, limit int) ([]models.Message, error) {
	var messages []models.Message
	subQuery := app.DB.Model(&models.Follower{}).Select("whom_id").Where("who_id = ?", userID)
	result := app.DB.
			Select("message.*, user.username, user.email").
			Joins("JOIN user ON user.user_id = message.author_id").
			Where("message.flagged = 0 AND (user.user_id = ? OR user.user_id IN (?))", userID, subQuery).
			Order("message.pub_date DESC").
			Limit(limit).
			Find(&messages)
	return messages, result.Error
}

func (app *App) getUserMessages(userID int, limit int) ([]models.Message, error) {
	var messages []models.Message
	result := app.DB.
			Select("message.*, user.username, user.email").
			Joins("JOIN user ON user.user_id = message.author_id").
			Where("message.flagged = 0 AND message.author_id = ?", userID).
			Order("message.pub_date DESC").
			Limit(limit).
			Find(&messages)
	return messages, result.Error
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
	var user models.User
	result := app.DB.Select("user_id").Where("username = ?", username).First(&user)
	if result.Error != nil {
			if result.Error.Error() == "record not found" {
					return 0, nil
			}
			return 0, result.Error
	}
	return user.UserID, nil
}

func (app *App) followUser(followerID int, followedID int) error {
	return app.DB.Create(&models.Follower{WhoId: followerID, WhomId: followedID}).Error
}

func (app *App) unfollowUser(followerID int, followedID int) error {
	return app.DB.Where("who_id = ? AND whom_id = ?", followerID, followedID).Delete(&models.Follower{}).Error
}

func (app *App) isFollowing(followerID int, followedID int) (bool, error) {
	var count int64
	result := app.DB.Model(&models.Follower{}).
			Where("who_id = ? AND whom_id = ?", followerID, followedID).
			Count(&count)
	return count > 0, result.Error
}

func (app *App) getUserById(userID int) (*models.User, error) {
	var user models.User
	result := app.DB.First(&user, userID)
	if result.Error != nil {
			if result.Error.Error() == "record not found" {
					return nil, nil
			}
			return nil, result.Error
	}
	return &user, nil
}

func (app *App) addUser(username string, email string, pwHash string) error {
	return app.DB.Create(&models.User{Username: username, Email: email, PwHash: pwHash}).Error
}

func (app *App) insertMessage(authorID int, text string) error {
	return app.DB.Create(&models.Message{
			AuthorId: authorID,
			Text:     text,
			PubDate:  int(time.Now().Unix()),
			Flagged:  0,
	}).Error
}

func (app *App) getLatestMessages(limit int, userID *int) ([]models.Message, error) {
	var messages []models.Message
	query := app.DB.
			Select("message.*, user.username, user.email").
			Joins("JOIN user ON user.user_id = message.author_id").
			Where("message.flagged = 0").
			Order("message.pub_date DESC").
			Limit(limit)
	if userID != nil {
			query = query.Where("message.author_id = ?", *userID)
	}
	result := query.Find(&messages)
	return messages, result.Error
}

func (app *App) getUserFollowing(userID int, limit int) ([]string, error) {
	var usernames []string
	result := app.DB.Model(&models.User{}).
			Joins("JOIN follower ON follower.whom_id = user.user_id").
			Where("follower.who_id = ?", userID).
			Limit(limit).
			Pluck("user.username", &usernames)
	return usernames, result.Error
}
