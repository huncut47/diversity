package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"minitwit/internal/models"
	"minitwit/internal/utils"

	"github.com/go-chi/chi/v5"
)

type TimelinePageData struct {
	User     *models.User
	Messages []models.Message
	Endpoint string
}

func (app *App) TimelineHandler(w http.ResponseWriter, r *http.Request) {
	app.Logger.Info("Received request for timeline", "method", r.Method, "path", r.URL.Path)
	page := TimelinePageData{
		User:     app.getUserFromContext(r),
		Messages: []models.Message{},
		Endpoint: "timeline",
	}
	if page.User == nil {
		app.Logger.Info("No user in context, redirecting to public timeline")
		http.Redirect(w, r, "/public", http.StatusSeeOther)
		return
	}
	app.Logger.Info("Loading timeline for user", "user_id", page.User.UserID, "username", page.User.Username)
	messages, err := app.getTimelineMessages(page.User.UserID, 100)
	if err != nil {
		app.Logger.Error("Failed to load timeline", "error", err)
		InternalServerErrorsTotal.WithLabelValues("/", "GET").Inc()
		http.Error(w, "Failed to load timeline", http.StatusInternalServerError)
	}
	page.Messages = messages

	err = app.Pages["timeline"].ExecuteTemplate(w, "layout", page)
	if err != nil {
		InternalServerErrorsTotal.WithLabelValues("/", "GET").Inc()
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
		app.Logger.Error("Failed to load public timeline", "error", err)
		http.Error(w, "Failed to load public timeline", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/public", "GET").Inc()
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
		app.Logger.Error("Failed to load user for profile", "username", username, "error", err)
		http.Error(w, "Failed to load user profile", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/{username}", "GET").Inc()
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
			app.Logger.Error("Failed to check following status", "follower_id", page.User.UserID, "followed_id", profileUser.UserID, "error", err)
			http.Error(w, "Failed to load user profile", http.StatusInternalServerError)
			InternalServerErrorsTotal.WithLabelValues("/{username}", "GET").Inc()
			return
		}
		page.Following = following
	}

	messages, err := app.getUserMessages(profileUser.UserID, 100)
	if err != nil {
		app.Logger.Error("Failed to load user timeline", "user_id", profileUser.UserID, "error", err)
		http.Error(w, "Failed to load user timeline", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/{username}", "GET").Inc()
		return
	}
	page.Messages = messages

	err = app.Pages["timeline"].ExecuteTemplate(w, "layout", page)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/{username}", "GET").Inc()
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
		app.Logger.Info("Received login request", "method", r.Method, "path", r.URL.Path)
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
				InternalServerErrorsTotal.WithLabelValues("/login", "POST").Inc()
			}
			return
		}

		session, err := app.Store.Get(r, "session")
		if err != nil {
			app.Logger.Error("Failed to get session", "error", err)
			http.Error(w, "Failed to get session", http.StatusInternalServerError)
			InternalServerErrorsTotal.WithLabelValues("/{username}", "GET").Inc()
			return
		}

		session.Values["user_id"] = user.UserID
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, "Failed to save session", http.StatusInternalServerError)
			InternalServerErrorsTotal.WithLabelValues("/{username}", "PUT").Inc()
			return
		}
		app.Logger.Info("User logged in", "user_id", user.UserID, "username", user.Username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	err := app.Pages["login"].ExecuteTemplate(w, "layout", page)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/{username}", "GET").Inc()
	}
}

type RegisterPageData struct {
	User     *models.User
	Username string
	Email    string
	Error    string
}

func (app *App) RegisterDispatcher(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") == "application/json" {
		app.RegisterAPIHandler(w, r)
	} else {
		app.RegisterHandler(w, r)
	}
}

func (app *App) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	page := RegisterPageData{
		User:     app.getUserFromContext(r),
		Username: "",
		Email:    "",
		Error:    "",
	}

	isAPI := false

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
				app.Logger.Error("Failed to decode registration request", "error", err)
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				InternalServerErrorsTotal.WithLabelValues("/register", "POST").Inc()
				return
			}
			username = req.Username
			if username == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				InternalServerErrorsTotal.WithLabelValues("/register", "POST").Inc()
				err := json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error": "missing username"})
				if err != nil {
					app.Logger.Error("Failed to encode error response", "error", err)
				}
				return
			}
			email = req.Email
			if email == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				InternalServerErrorsTotal.WithLabelValues("/register", "POST").Inc()
				err := json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error": "invalid email"})
				if err != nil {
					app.Logger.Error("Failed to encode error response", "error", err)
				}
				return
			}
			password = req.Password
			if password == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				InternalServerErrorsTotal.WithLabelValues("/register", "POST").Inc()
				err := json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error": "password missing"})
				if err != nil {
					app.Logger.Error("Failed to encode error response", "error", err)
				}
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
					InternalServerErrorsTotal.WithLabelValues("/register", "GET").Inc()
				}
				return
			}
		} else {
			app.Logger.Error("Unsupported Content-Type for registration", "Content-Type", r.Header.Get("Content-Type"))
			http.Error(w, "Unsupported Content-Type", http.StatusUnsupportedMediaType)
			return
		}

		app.Logger.Info("Received registration request", "username", username, "email", email)

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
				InternalServerErrorsTotal.WithLabelValues("/register", "POST").Inc()
				err := json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error": page.Error})
				if err != nil {
					app.Logger.Error("Failed to encode error response", "error", err)
				}
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
}

func (app *App) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := app.Store.Get(r, "session")
	delete(session.Values, "user_id")
	err := session.Save(r, w)
	if err != nil {
		app.Logger.Error("Failed to save session", "error", err)
	}

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

	app.Logger.Info("Adding message for user", "user_id", user.UserID, "username", user.Username, "text_length", len(text))

	err := app.insertMessage(user.UserID, text)
	if err != nil {
		http.Error(w, "Failed to add message", http.StatusInternalServerError)
		PostsTotal.Inc()
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *App) FollowUserHandler(w http.ResponseWriter, r *http.Request) {
	user := app.getUserFromContext(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := chi.URLParam(r, "username")
	profileUser, err := app.getUserByUsername(username)
	if err != nil {
		app.Logger.Error("Failed to load user for follow", "username", username, "error", err)
		http.Error(w, "Failed to load user profile", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/{username}/follow", "GET").Inc()
		return
	}
	if profileUser == nil {
		http.NotFound(w, r)
		return
	}

	err = app.followUser(user.UserID, profileUser.UserID)
	if err != nil {
		app.Logger.Error("Failed to follow user", "follower_id", user.UserID, "followed_id", profileUser.UserID, "error", err)
		http.Error(w, "Failed to follow user", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/{username}/follow", "POST").Inc()
		return
	}

	http.Redirect(w, r, "/"+username, http.StatusSeeOther)
}

func (app *App) UnfollowUserHandler(w http.ResponseWriter, r *http.Request) {
	user := app.getUserFromContext(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := chi.URLParam(r, "username")
	profileUser, err := app.getUserByUsername(username)
	if err != nil {
		app.Logger.Error("Failed to load user for unfollow", "username", username, "error", err)
		http.Error(w, "Failed to load user profile", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/{username}/unfollow", "GET").Inc()
		return
	}
	if profileUser == nil {
		http.NotFound(w, r)
		return
	}

	err = app.unfollowUser(user.UserID, profileUser.UserID)
	if err != nil {
		app.Logger.Error("Failed to unfollow user", "follower_id", user.UserID, "followed_id", profileUser.UserID, "error", err)
		http.Error(w, "Failed to unfollow user", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/{username}/unfollow", "POST").Inc()
		return
	}

	http.Redirect(w, r, "/"+username, http.StatusSeeOther)
}

func (app *App) getUserFromContext(r *http.Request) *models.User {
	user, ok := r.Context().Value(userContextKey).(*models.User)
	if !ok {
		return nil
	}
	app.Logger.Info("User loaded from context", "user_id", user.UserID, "username", user.Username)
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
		app.Logger.Error("Failed to get user ID", "username", username, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/fllws/{username}", "GET").Inc()
		return
	}
	if userID == 0 {
		http.NotFound(w, r)
		return
	}

	followers, err := app.getUserFollowing(userID, limit)
	if err != nil {
		app.Logger.Error("Failed to get followers", "user_id", userID, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/fllws/{username}", "GET").Inc()
		return
	}

	followersJSON, err := json.Marshal(map[string]interface{}{
		"follows": followers,
	})
	if err != nil {
		app.Logger.Error("Failed to marshal followers to JSON", "user_id", userID, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/fllws/{username}", "GET").Inc()
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(followersJSON)
	if err != nil {
		app.Logger.Error("Failed to write response", "error", err)
	}
}

func (app *App) FollowUserAPIHandler(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	defer func() {
		if err := r.Body.Close(); err != nil {
			app.Logger.Error("Failed to close request body", "error", err)
		}
	}()

	userID, err := app.getUserId(username)
	if err != nil {
		app.Logger.Error("Failed to get user ID", "username", username, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/fllws/{username}", "GET").Inc()
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
		app.Logger.Error("Failed to decode follow/unfollow request", "username", username, "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		InvalidRequestsTotal.WithLabelValues("/fllws/{username}", "Invalid request body")
		return
	}

	if req.Follow != "" {
		followUserID, err := app.getUserId(req.Follow)
		if err != nil {
			app.Logger.Error("Failed to get user ID for follow", "username", req.Follow, "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			InternalServerErrorsTotal.WithLabelValues("/fllws/{username}", "GET").Inc()
			return
		}
		if followUserID == 0 {
			http.NotFound(w, r)
			return
		}
		err = app.followUser(userID, followUserID)
		if err != nil {
			app.Logger.Error("Failed to follow user", "user_id", userID, "followed_id", followUserID, "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			InternalServerErrorsTotal.WithLabelValues("/fllws/{username}", "POST").Inc()
			return
		}

	} else if req.Unfollow != "" {
		unfollowUserID, err := app.getUserId(req.Unfollow)
		if err != nil {
			app.Logger.Error("Failed to get user ID for unfollow", "username", req.Unfollow, "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			InternalServerErrorsTotal.WithLabelValues("/fllws/{username}", "GET").Inc()
			return
		}
		if unfollowUserID == 0 {
			http.NotFound(w, r)
			return
		}
		err = app.unfollowUser(userID, unfollowUserID)
		if err != nil {
			app.Logger.Error("Failed to unfollow user", "user_id", userID, "unfollowed_id", unfollowUserID, "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			InternalServerErrorsTotal.WithLabelValues("/fllws/{username}", "POST").Inc()
			return
		}
	} else {
		http.Error(w, "Invalid request body: must contain 'follow' or 'unfollow'", http.StatusBadRequest)
		InvalidRequestsTotal.WithLabelValues("/fllws/{username}", "'follow' or 'unfollow' not in request body")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (app *App) LatestOperationHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(map[string]interface{}{"latest": app.GetLatest()})
	if err != nil {
		app.Logger.Error("Failed to encode latest response", "error", err)
	}
}

func (app *App) GetMessagesHandler(w http.ResponseWriter, r *http.Request) {
	no := r.URL.Query().Get("no")
	if no == "" {
		no = "100"
	}
	limit, err := strconv.Atoi(no)
	if err != nil {
		limit = 100
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			app.Logger.Error("Failed to close request body", "error", err)
		}
	}()

	messages, err := app.getLatestMessages(limit, nil)
	if err != nil {
		app.Logger.Error("Failed to load latest messages")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/msgs", "GET").Inc()
		return
	}
	messagesJSON, err := json.Marshal(messages)
	if err != nil {
		app.Logger.Error("Failed Marshalize messages to JSON")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/msgs", "GET").Inc()
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(messagesJSON)
	if err != nil {
		app.Logger.Error("Failed to write response", "error", err)
	}
}

func (app *App) GetUserMessagesHandler(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	no := r.URL.Query().Get("no")
	if no == "" {
		no = "100"
	}
	limit, err := strconv.Atoi(no)
	if err != nil {
		limit = 100
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			app.Logger.Error("Failed to close request body", "error", err)
		}
	}()

	userID, err := app.getUserId(username)
	if err != nil {
		app.Logger.Error("Failed to get user ID", "username", username, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/msgs/{username}", "GET").Inc()
		return
	}
	if userID == 0 {
		http.NotFound(w, r)
		return
	}

	messages, err := app.getLatestMessages(limit, &userID)
	if err != nil {
		app.Logger.Error("Failed to load latest messages")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/msgs/{username}", "GET").Inc()
		return
	}
	messagesJSON, err := json.Marshal(messages)
	if err != nil {
		app.Logger.Error("Failed Marshalize messages to JSON")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/msgs/{username}", "GET").Inc()
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(messagesJSON)
	if err != nil {
		app.Logger.Error("Failed to write response", "error", err)
	}
}

func (app *App) PostUserMessageHandler(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	defer func() {
		if err := r.Body.Close(); err != nil {
			app.Logger.Error("Failed to close request body", "error", err)
		}
	}()
	var req struct {
		Content  string `json:"content"`
		Username string `json:"username"`
	}

	user, err := app.getUserByUsername(username)
	if err != nil {
		app.Logger.Error("Failed to check existing user", "username", req.Username, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/msgs/{username}", "POST").Inc()
		return
	}
	if user == nil {
		http.Error(w, "User does not exist", http.StatusBadRequest)
		InvalidRequestsTotal.WithLabelValues("/msgs/{username}", "User does not exist")
		return
	}

	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		app.Logger.Error("Failed to decode registration request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		InvalidRequestsTotal.WithLabelValues("/msgs/{username}", "Invalid request body")
		return
	}

	if req.Content == "" {
		http.Error(w, "Messages must contain text", http.StatusBadRequest)
		InvalidRequestsTotal.WithLabelValues("/msgs/{username}", "Messages must contain text")
		return
	}

	err = app.insertMessage(user.UserID, req.Content)
	if err != nil {
		app.Logger.Error("Failed to add message to database", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/msgs/{username}", "GET").Inc()
		return
	}

	w.WriteHeader(http.StatusNoContent)
	PostsTotal.Inc()
}

func (app *App) RegisterAPIHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := r.Body.Close(); err != nil {
			app.Logger.Error("Failed to close request body", "error", err)
		}
	}()

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"pwd"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		app.Logger.Error("Failed to decode registration request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		InvalidRequestsTotal.WithLabelValues("/register", "Invalid request body")
		return
	}

	if req.Username == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		err := json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error_msg": "You have to enter a username"})
		if err != nil {
			app.Logger.Error("Failed to encode error response", "error", err)
		}
		InvalidRequestsTotal.WithLabelValues("/register", "You have to enter a username")
		return
	}
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		err := json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error_msg": "You have to enter a valid email address"})
		if err != nil {
			app.Logger.Error("Failed to encode error response", "error", err)
		}
		InvalidRequestsTotal.WithLabelValues("/register", "You have to enter a valid e-mail adress.")
		return
	}
	if req.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		err := json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error_msg": "You have to enter a password"})
		if err != nil {
			app.Logger.Error("Failed to encode error response", "error", err)
		}
		InvalidRequestsTotal.WithLabelValues("/register", "You have to enter a password")
		return
	}

	existingUser, err := app.getUserByUsername(req.Username)
	if err != nil {
		app.Logger.Error("Failed to check existing user", "username", req.Username, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		InternalServerErrorsTotal.WithLabelValues("/register", "POST").Inc()
		return
	}
	if existingUser != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		err := json.NewEncoder(w).Encode(map[string]interface{}{"status": http.StatusBadRequest, "error_msg": "The username is already taken"})
		if err != nil {
			app.Logger.Error("Failed to encode error response", "error", err)
		}
		InvalidRequestsTotal.WithLabelValues("/register", "Username is already taken")
		return
	}

	pwHash, err := utils.GeneratePasswordHash(req.Password)
	if err != nil {
		app.Logger.Error("Failed to hash password", "error", err)
		http.Error(w, "Failed to hash password", http.StatusBadRequest)
		InvalidRequestsTotal.WithLabelValues("/register", "Failed to hash password")
		return
	}

	err = app.addUser(req.Username, req.Email, pwHash)
	if err != nil {
		app.Logger.Error("Failed to add user", "username", req.Username, "error", err)
		http.Error(w, "Failed to add user", http.StatusBadRequest)
		InvalidRequestsTotal.WithLabelValues("/register", "Failed to add user")
		return
	}

	w.WriteHeader(http.StatusNoContent)
	NewRegisteredUsers.Inc()
}

func (app *App) HealthHandler(w http.ResponseWriter, r *http.Request) {
	sqlDB, err := app.DB.DB()
	if err != nil || sqlDB.Ping() != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		if _, err := w.Write([]byte(`{"status":"db_down"}`)); err != nil {
			app.Logger.Error("Failed to write response", "error", err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
		app.Logger.Error("Failed to write response", "error", err)
	}
}
