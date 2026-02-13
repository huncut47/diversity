package web

import (
	"encoding/json"
	"log/slog"
	"minitwit/internal/models"
	"minitwit/internal/utils"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

type TimelinePageData struct {
	User     *models.User
	Messages []models.Message
	Endpoint string
}

func (app *App) TimelineHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("Received request for timeline", "method", r.Method, "path", r.URL.Path)
	page := TimelinePageData{
		User:     app.getUserFromContext(r),
		Messages: []models.Message{},
		Endpoint: "timeline",
	}
	if page.User == nil {
		slog.Info("No user in context, redirecting to public timeline")
		http.Redirect(w, r, "/public", http.StatusSeeOther)
		return
	}
	slog.Info("Loading timeline for user", "user_id", page.User.UserID, "username", page.User.Username)
	messages, err := app.getTimelineMessages(page.User.UserID, 100)
	if err != nil {
		slog.Error("Failed to load timeline", "error", err)
		http.Error(w, "Failed to load timeline", http.StatusInternalServerError)
	}
	page.Messages = messages

	err = app.Pages["timeline"].ExecuteTemplate(w, "layout", page)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type PublicTimelinePageData struct {
	User     *models.User
	Messages []models.Message
	Endpoint string
}

func (app *App) PublicTimelineHandler(w http.ResponseWriter, r *http.Request) {
	page := PublicTimelinePageData{
		User:     app.getUserFromContext(r),
		Messages: []models.Message{},
		Endpoint: "public_timeline",
	}

	messages, err := app.getPublicMessages(100)
	if err != nil {
		slog.Error("Failed to load public timeline", "error", err)
		http.Error(w, "Failed to load public timeline", http.StatusInternalServerError)
	}
	page.Messages = messages

	err = app.Pages["timeline"].ExecuteTemplate(w, "layout", page)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type UserTimelinePageData struct {
	User        *models.User
	Messages    []models.Message
	ProfileUser *models.User
	Following   bool
	Endpoint    string
}

func (app *App) UserTimelineHandler(w http.ResponseWriter, r *http.Request) {
	page := UserTimelinePageData{
		User:      app.getUserFromContext(r),
		Messages:  []models.Message{},
		Endpoint:  "user_timeline",
		Following: false,
	}

	username := chi.URLParam(r, "username")
	profileUser, err := app.getUserByUsername(username)
	if err != nil {
		slog.Error("Failed to load user for profile", "username", username, "error", err)
		http.Error(w, "Failed to load user profile", http.StatusInternalServerError)
		return
	}
	if profileUser == nil {
		http.NotFound(w, r)
		return
	}
	page.ProfileUser = profileUser

	// Check if the current user is following the profile user
	if page.User != nil {
		following, err := app.isFollowing(page.User.UserID, profileUser.UserID)
		if err != nil {
			slog.Error("Failed to check following status", "follower_id", page.User.UserID, "followed_id", profileUser.UserID, "error", err)
			http.Error(w, "Failed to load user profile", http.StatusInternalServerError)
			return
		}
		page.Following = following
	}

	messages, err := app.getUserMessages(profileUser.UserID, 100)
	if err != nil {
		slog.Error("Failed to load user timeline", "user_id", profileUser.UserID, "error", err)
		http.Error(w, "Failed to load user timeline", http.StatusInternalServerError)
		return
	}
	page.Messages = messages

	err = app.Pages["timeline"].ExecuteTemplate(w, "layout", page)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

}

type LoginPageData struct {
	User     *models.User
	Username string
	Error    string
}

func (app *App) LoginHandler(w http.ResponseWriter, r *http.Request) {
	page := LoginPageData{
		User:     app.getUserFromContext(r),
		Username: "",
		Error:    "",
	}

	if page.User != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}

	if r.Method == http.MethodPost {
		// Handle login form submission
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := app.getUserByUsername(username)
		if err != nil {
			page.Error = "Internal server error"
		}
		if user == nil || !utils.CheckPasswordHash(user.PwHash, password) {
			page.Error = "Invalid username or password"
		}

		// Set user in session if login is successful
		if page.Error == "" {
			session, _ := app.Store.Get(r, "session")
			session.Values["user_id"] = user.UserID
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	err := app.Pages["login"].ExecuteTemplate(w, "layout", page)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type RegisterPageData struct {
	User     *models.User
	Username string
	Email    string
	Error    string
}

func (app *App) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	page := RegisterPageData{
		User:     app.getUserFromContext(r),
		Username: "",
		Email:    "",
		Error:    "",
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		password2 := r.FormValue("password2")

		if password != password2 {
			page.Error = "Passwords do not match"
		}
		if username == "" || email == "" || password == "" {
			page.Error = "All fields are required"
		}

		existingUser, err := app.getUserByUsername(username)
		if err != nil {
			page.Error = "Internal server error"
		}
		if existingUser != nil {
			page.Error = "Username already taken"
		}

		if page.Error == "" {
			pwHash, err := utils.GeneratePasswordHash(password)
			if err != nil {
				page.Error = "Internal server error"
			} else {
				err = app.addUser(username, email, pwHash)
				if err != nil {
					page.Error = "Internal server error"
				} else {
					http.Redirect(w, r, "/login", http.StatusSeeOther)
					return
				}
			}
		}
	}

	err := app.Pages["register"].ExecuteTemplate(w, "layout", page)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (app *App) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := app.Store.Get(r, "session")
	delete(session.Values, "user_id")
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *App) AddMessageHandler(w http.ResponseWriter, r *http.Request) {
	user := app.getUserFromContext(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	text := r.FormValue("text")
	if text == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	slog.Info("Adding message for user", "user_id", user.UserID, "username", user.Username, "text_length", len(text))

	err := app.insertMessage(user.UserID, text)
	if err != nil {
		http.Error(w, "Failed to add message", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *App) FollowUserHandler(w http.ResponseWriter, r *http.Request) {
	user := app.getUserFromContext(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	username := chi.URLParam(r, "username")
	profileUser, err := app.getUserByUsername(username)
	if err != nil {
		slog.Error("Failed to load user for follow", "username", username, "error", err)
		http.Error(w, "Failed to load user profile", http.StatusInternalServerError)
		return
	}
	if profileUser == nil {
		http.NotFound(w, r)
		return
	}

	err = app.followUser(user.UserID, profileUser.UserID)
	if err != nil {
		slog.Error("Failed to follow user", "follower_id", user.UserID, "followed_id", profileUser.UserID, "error", err)
		http.Error(w, "Failed to follow user", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/"+username, http.StatusSeeOther)
}

func (app *App) UnfollowUserHandler(w http.ResponseWriter, r *http.Request) {
	user := app.getUserFromContext(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	username := chi.URLParam(r, "username")
	profileUser, err := app.getUserByUsername(username)
	if err != nil {
		slog.Error("Failed to load user for unfollow", "username", username, "error", err)
		http.Error(w, "Failed to load user profile", http.StatusInternalServerError)
		return
	}
	if profileUser == nil {
		http.NotFound(w, r)
		return
	}

	err = app.unfollowUser(user.UserID, profileUser.UserID)
	if err != nil {
		slog.Error("Failed to unfollow user", "follower_id", user.UserID, "followed_id", profileUser.UserID, "error", err)
		http.Error(w, "Failed to unfollow user", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/"+username, http.StatusSeeOther)
}

func (app *App) getUserFromContext(r *http.Request) *models.User {
	user, ok := r.Context().Value("user").(*models.User)
	if !ok {
		return nil
	}
	slog.Info("User loaded from context", "user_id", user.UserID, "username", user.Username)
	return user
}

func (app *App) FollowersHandler(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	no := r.URL.Query().Get("no")
	if no == "" {
		no = "100"
	}
	limit, err := strconv.Atoi(no)
	if err != nil {
		limit = 100
	}

	userID, err := app.getUserId(username)
	if err != nil {
		slog.Error("Failed to get user ID", "username", username, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if userID == 0 {
		http.NotFound(w, r)
		return
	}

	followers, err := app.getUserFollowing(userID, limit)
	if err != nil {
		slog.Error("Failed to get followers", "user_id", userID, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	followersJSON, err := json.Marshal(map[string]interface{}{
		"follows": followers,
	})
	if err != nil {
		slog.Error("Failed to marshal followers to JSON", "user_id", userID, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(followersJSON)
}
