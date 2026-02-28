package web

import (
	"encoding/json"
	"log/slog"
	"minitwit/internal/models"
	"minitwit/internal/utils"
	"net/http"
	"strconv"
	"strings"

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
		return
	}

	if r.Method == http.MethodPost {
		slog.Info("Received login request", "method", r.Method, "path", r.URL.Path)
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := app.getUserByUsername(username)
		if err != nil {
			page.Error = "Internal server error"
		}
		if user == nil || !utils.CheckPasswordHash(user.PwHash, password) {
			page.Error = "Invalid username or password"
			err = app.Pages["login"].ExecuteTemplate(w, "layout", page)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		session, err := app.Store.Get(r, "session")
		if err != nil {
			slog.Error("Failed to get session", "error", err)
			http.Error(w, "Failed to get session", http.StatusInternalServerError)
			return
		}

		session.Values["user_id"] = user.UserID
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, "Failed to save session", http.StatusInternalServerError)
			return
		}
		slog.Info("User logged in", "user_id", user.UserID, "username", user.Username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	err := app.Pages["login"].ExecuteTemplate(w, "layout", page)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	return
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

	var isAPI bool = false

	if r.Method == http.MethodPost {
		username := ""
		email := ""
		password := ""

		// Examine header to see if form submission or JSON body
		if r.Header.Get("Content-Type") == "application/json" {
			isAPI = true
			// Parse the JSON body
			var req struct {
				Username string `json:"username"`
				Email    string `json:"email"`
				Password string `json:"pwd"`
			}
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				slog.Error("Failed to decode registration request", "error", err)
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			username = req.Username
			if username == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error": "missing username"})
				return
			}
			email = req.Email
			if email == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error": "invalid email"})
				return
			}
			password = req.Password
			if password == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error": "password missing"})
				return
			}
		} else if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
			username = r.FormValue("username")
			email = r.FormValue("email")
			password = r.FormValue("password")
			password2 := r.FormValue("password2")

			if password != password2 {
				page.Error = "Passwords do not match"
				err := app.Pages["register"].ExecuteTemplate(w, "layout", page)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
				return
			}
		} else {
			slog.Error("Unsupported Content-Type for registration", "Content-Type", r.Header.Get("Content-Type"))
			http.Error(w, "Unsupported Content-Type", http.StatusUnsupportedMediaType)
			return
		}

		slog.Info("Received registration request", "username", username, "email", email)

		if username == "" || email == "" || password == "" {
			page.Error = "All fields are required"
		}

		existingUser, err := app.getUserByUsername(username)
		if err != nil {
			page.Error = "Internal server error"
		}
		if existingUser != nil {
			page.Error = "Username already taken"
			if isAPI {
				// Write error response for API request
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error": page.Error})
				return
			}
		}

		if page.Error == "" {
			pwHash, err := utils.GeneratePasswordHash(password)
			if err != nil {
				page.Error = "Internal server error"
			} else {
				err = app.addUser(username, email, pwHash)
				if err != nil {
					page.Error = "Internal server error"
				} else if !isAPI {
					http.Redirect(w, r, "/login", http.StatusSeeOther)
					return
				} else {
					w.WriteHeader(http.StatusOK)
					return
				}
			}
		}
	}

	err := app.Pages["register"].ExecuteTemplate(w, "layout", page)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	return
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
	latest := r.URL.Query().Get("latest")
	if latest != "" {
		latestInt, err := strconv.Atoi(latest)
		if err != nil {
			slog.Error("Failed to convert latest to integer", "latest", latest, "error", err)
			http.Error(w, "Invalid latest parameter", http.StatusBadRequest)
			return
		}
		app.Latest = latestInt

	}
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

func (app *App) FollowUserAPIHandler(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	latest := r.URL.Query().Get("latest")
	if latest != "" {
		latestInt, err := strconv.Atoi(latest)
		if err != nil {
			slog.Error("Failed to convert latest to integer", "latest", latest, "error", err)
			http.Error(w, "Invalid latest parameter", http.StatusBadRequest)
			return
		}
		app.Latest = latestInt
	}

	defer r.Body.Close()

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

	var req struct {
		Follow   string `json:"follow,omitempty"`
		Unfollow string `json:"unfollow,omitempty"`
	}

	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		slog.Error("Failed to decode follow/unfollow request", "username", username, "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Follow != "" {
		followUserID, err := app.getUserId(req.Follow)
		if err != nil {
			slog.Error("Failed to get user ID for follow", "username", req.Follow, "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if followUserID == 0 {
			http.NotFound(w, r)
			return
		}
		err = app.followUser(userID, followUserID)
		if err != nil {
			slog.Error("Failed to follow user", "user_id", userID, "followed_id", followUserID, "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

	} else if req.Unfollow != "" {
		unfollowUserID, err := app.getUserId(req.Unfollow)
		if err != nil {
			slog.Error("Failed to get user ID for unfollow", "username", req.Unfollow, "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if unfollowUserID == 0 {
			http.NotFound(w, r)
			return
		}
		err = app.unfollowUser(userID, unfollowUserID)
		if err != nil {
			slog.Error("Failed to unfollow user", "user_id", userID, "unfollowed_id", unfollowUserID, "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "Invalid request body: must contain 'follow' or 'unfollow'", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (app *App) LatestOperationHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"latest": app.Latest})
}

func (app *App) GetMessagesHandler(w http.ResponseWriter, r *http.Request) {
	latest := r.URL.Query().Get("latest")
	if latest != "" {
		latestInt, err := strconv.Atoi(latest)
		if err != nil {
			slog.Error("Failed to convert latest to integer", "latest", latest, "error", err)
			http.Error(w, "Invalid latest parameter", http.StatusBadRequest)
			return
		}
		app.Latest = latestInt
	}
	no := r.URL.Query().Get("no")
	if no == "" {
		no = "100"
	}
	limit, err := strconv.Atoi(no)
	if err != nil {
		limit = 100
	}

	defer r.Body.Close()

	messages, err := app.getLatestMessages(limit, nil)
	if err != nil {
		slog.Error("Failed to load latest messages")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	messagesJSON, err := json.Marshal(messages)
	if err != nil {
		slog.Error("Failed Marshalize messages to JSON")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(messagesJSON)
}
func (app *App) GetUserMessagesHandler(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	latest := r.URL.Query().Get("latest")
	if latest != "" {
		latestInt, err := strconv.Atoi(latest)
		if err != nil {
			slog.Error("Failed to convert latest to integer", "latest", latest, "error", err)
			http.Error(w, "Invalid latest parameter", http.StatusBadRequest)
			return
		}
		app.Latest = latestInt
	}
	no := r.URL.Query().Get("no")
	if no == "" {
		no = "100"
	}
	limit, err := strconv.Atoi(no)
	if err != nil {
		limit = 100
	}

	defer r.Body.Close()

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

	messages, err := app.getLatestMessages(limit, &userID)
	if err != nil {
		slog.Error("Failed to load latest messages")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	messagesJSON, err := json.Marshal(messages)
	if err != nil {
		slog.Error("Failed Marshalize messages to JSON")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(messagesJSON)

}

func (app *App) PostUserMessageHandler(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	latest := r.URL.Query().Get("latest")
	if latest != "" {
		latestInt, err := strconv.Atoi(latest)
		if err != nil {
			slog.Error("Failed to convert latest to integer", "latest", latest, "error", err)
			http.Error(w, "Invalid latest parameter", http.StatusBadRequest)
			return
		}
		app.Latest = latestInt
	}

	defer r.Body.Close()

	var req struct {
		Content  string `json:"content"`
		Username string `json:"username"`
	}

	user, err := app.getUserByUsername(username)
	if err != nil {
		slog.Error("Failed to check existing user", "username", req.Username, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "User do not exist", http.StatusBadRequest)
		return
	}

	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		slog.Error("Failed to decode registration request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Messages must contain text", http.StatusBadRequest)
		return
	}

	err = app.insertMessage(user.UserID, req.Content)
	if err != nil {
		slog.Error("Failed to add message to database", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)

}

func (app *App) RegisterAPIHandler(w http.ResponseWriter, r *http.Request) {
	latest := r.URL.Query().Get("latest")
	if latest != "" {
		latestInt, err := strconv.Atoi(latest)
		if err != nil {
			slog.Error("Failed to convert latest to integer", "latest", latest, "error", err)
			http.Error(w, "Invalid latest parameter", http.StatusBadRequest)
			return
		}
		app.Latest = latestInt
	}

	defer r.Body.Close()

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"pwd"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		slog.Error("Failed to decode registration request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error_msg": "You have to enter a username"})
		return
	}
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error_msg": "You have to enter a valid email address"})
		return
	}
	if req.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error_msg": "You have to enter a password"})
		return
	}

	existingUser, err := app.getUserByUsername(req.Username)
	if err != nil {
		slog.Error("Failed to check existing user", "username", req.Username, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if existingUser != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error_msg": "The username is already taken"})
		return
	}

	pwHash, err := utils.GeneratePasswordHash(req.Password)
	if err != nil {
		slog.Error("Failed to hash password", "error", err)
		http.Error(w, "Failed to hash password", http.StatusBadRequest)
		return
	}

	err = app.addUser(req.Username, req.Email, pwHash)
	if err != nil {
		slog.Error("Failed to add user", "username", req.Username, "error", err)
		http.Error(w, "Failed to add user", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
