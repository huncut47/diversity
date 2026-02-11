package main

import (
	"context"
	"crypto/md5"
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
)

const DATABASE = "./minitwit.db"

var db *sql.DB

var tmpl *template.Template

var store = sessions.NewCookieStore([]byte("dev_key"))

type User struct {
	UserID   int
	Username string
	Email    string
	PwHash   string
}

type Follower struct {
	WhoId  int
	WhomId int
}

type Message struct {
	MessageId int
	AuthorId  int
	Text      string
	PubDate   int
	Flagged   int
	Username  string
	Email     string
}

func main() {
	var err error
	db, err = connectDb()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = initDb()
	if err != nil {
		log.Fatal(err)
	}

	// Parse all the HTML templates in the "templates" directory
	tmpl = template.Must(template.ParseGlob("templates/*.html"))

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(authMiddleware)
	// r.Get("/", func(w http.ResponseWriter, r *http.Request) {
	// 	w.Write([]byte("welcome"))
	// })

	r.Get("/", timeline)
	r.Get("/public", publicTimeline)

	r.Get("/login", login)
	r.Post("/login", login)

	r.Get("/register", register)
	r.Post("/register", register)

	r.Get("/logout", logout)

	r.Post("/add_message", addMessage)

	r.Get("/{username}/follow", followUser)
	r.Get("/{username}/unfollow", unfollowUser)
	r.Get("/{username}", userTimeline)

	// Handle the static files directory
	fs := http.FileServer(http.Dir("./static"))
	r.Handle("/static/*", http.StripPrefix("/static/", fs))

	slog.Info("Starting server on :3000")
	http.ListenAndServe(":3000", r)
}

func connectDb() (*sql.DB, error) {
	return sql.Open("sqlite3", DATABASE)
}

func initDb() error {
	content, err := os.ReadFile("schema.sql")
	if err != nil {
		return err
	}
	_, err = db.Exec(string(content))
	return err
}

func formatDatetime(timestamp int) string {
	t := time.Unix(int64(timestamp), 0).UTC()
	return t.Format("2006-01-02 @ 15:04")
}

func gravatarUrl(email string, size int) string {
	hash := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(email))))
	return fmt.Sprintf("http://www.gravatar.com/avatar/%x?d=identicon&s=%d", hash, size)
}

func getUserId(username string) (int, error) {
	var id int
	err := db.QueryRow("select user_id from user where username = ?", username).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}

func getUserById(userID int) (*User, error) {
	var u *User
	err := db.QueryRow("select user_id, username, email, pw_hash from user where user_id = ?", userID).Scan(&u.UserID, &u.Username, &u.Email, &u.PwHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func getUserByUsername(username string) (*User, error) {
	var u *User
	err := db.QueryRow("select user_id, username, email, pw_hash from user where username = ?", username).Scan(&u.UserID, &u.Username, &u.Email, &u.PwHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func getSessionUserID(r *http.Request) int {
	session, _ := store.Get(r, "session")

	log.Printf("getSessionUserID: session.Values = %#v", session.Values)

	userID, ok := session.Values["user_id"].(int)
	if !ok {
		return 0
	}
	return userID
}

func setSessionUserID(w http.ResponseWriter, r *http.Request, userID int) {
	session, err := store.Get(r, "session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["user_id"] = userID

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := getSessionUserID(r)

		if userID > 0 {
			user, err := getUserById(userID)
			if err == nil && user != nil {
				ctx := context.WithValue(r.Context(), "user", user)
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func scanMessages(rows *sql.Rows) ([]Message, error) {
	var messages []Message
	for rows.Next() {
		var m Message
		err := rows.Scan(&m.MessageId, &m.AuthorId, &m.Text, &m.PubDate, &m.Flagged, &m.Username, &m.Email)
		if err != nil {
			return nil, err
		}
		messages = append(messages, m)
	}
	return messages, rows.Err()
}

func getPublicMessages(limit int) ([]Message, error) {
	rows, err := db.Query(`
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

func getTimelineMessages(userID int, limit int) ([]Message, error) {
	rows, err := db.Query(`
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

func getUserMessages(userID int, limit int) ([]Message, error) {
	rows, err := db.Query(`
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

type TimelinePageData struct {
	Messages []Message
	User     *User
}

func insertMessage(authorID int, text string) error {
	_, err := db.Exec(`insert into message (author_id, text, pub_date, flagged)
            values (?, ?, ?, 0)`, authorID, text, time.Now().Unix())
	return err
}

func addUser(username string, email string, pwHash string) error {
	_, err := db.Exec(`insert into user (
                username, email, pw_hash) values (?, ?, ?)`, username, email, pwHash)
	return err
}

func addFollower(whoID int, whomID int) error {
	_, err := db.Exec(`insert into follower (who_id, whom_id) values (?, ?)`, whoID, whomID)
	return err
}

func removeFollower(whoID int, whomID int) error {
	_, err := db.Exec(`delete from follower where who_id=? and whom_id=?`, whoID, whomID)
	return err
}

func timeline(w http.ResponseWriter, r *http.Request) {
	if r.Context().Value("user") == nil {
		http.Redirect(w, r, "/public", http.StatusFound)
		return
	}

	messages, err := getTimelineMessages(getSessionUserID(r), 100)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.ExecuteTemplate(w, "layout", TimelinePageData{
		Messages: messages,
		User:     r.Context().Value("user").(*User),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type PublicTimelinePageData struct {
	Messages []Message
	User     *User
	Endpoint string
}

func publicTimeline(w http.ResponseWriter, r *http.Request) {
	messages, err := getPublicMessages(100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var user *User
	if r.Context().Value("user") != nil {
		user = r.Context().Value("user").(*User)
	}

	err = tmpl.ExecuteTemplate(w, "layout", PublicTimelinePageData{
		Messages: messages,
		User:     user,
		Endpoint: "public",
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type UserTimelinePageData struct {
	Messages []Message
	Endpoint string
	User     *User
}

func userTimeline(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	profileUser, err := getUserByUsername(username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if profileUser == nil {
		http.NotFound(w, r)
		return
	}

	messages, err := getTimelineMessages(profileUser.UserID, 100)

	err = tmpl.ExecuteTemplate(w, "layout", UserTimelinePageData{
		Messages: messages,
		Endpoint: username,
		User:     r.Context().Value("user").(*User),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func followUser(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	if r.Context().Value("user") == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	whomID, err := getUserId(username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if whomID == 0 {
		http.NotFound(w, r)
		return
	}

	err = addFollower(getSessionUserID(r), whomID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/%s", username), http.StatusFound)
}

func unfollowUser(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	if r.Context().Value("user") == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	whomID, err := getUserId(username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if whomID == 0 {
		http.NotFound(w, r)
		return
	}

	err = removeFollower(getSessionUserID(r), whomID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/%s", username), http.StatusFound)
}

func addMessage(w http.ResponseWriter, r *http.Request) {
	if r.Context().Value("user") == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	text := r.FormValue("text")
	if text != "" {
		err := insertMessage(getSessionUserID(r), text)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

type LoginPageData struct {
	Username string
	User     *User
	Error    string
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Context().Value("user") != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	var user *User
	if u := r.Context().Value("user"); u != nil {
		user = u.(*User)
	}
	data := LoginPageData{
		User: user,
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := getUserByUsername(username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if user == nil || user.PwHash != fmt.Sprintf("%x", md5.Sum([]byte(password))) {
			data.Error = "Invalid username or password"
			data.Username = username
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		} else {
			setSessionUserID(w, r, user.UserID)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	err := tmpl.ExecuteTemplate(w, "layout", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type RegisterPageData struct {
	Username string
	Email    string
	User     *User
	Error    string
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Context().Value("user") != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		password2 := r.FormValue("password2")

		if username == "" {
			data := RegisterPageData{
				Error: "You have to enter a username",
			}
			err := tmpl.ExecuteTemplate(w, "layout", data)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		if email == "" || !strings.Contains(email, "@") {
			data := RegisterPageData{
				Error: "You have to enter a valid email address",
			}
			err := tmpl.ExecuteTemplate(w, "layout", data)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		if password == "" {
			data := RegisterPageData{
				Error: "You have to enter a password",
			}
			err := tmpl.ExecuteTemplate(w, "layout", data)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		if password != password2 {
			data := RegisterPageData{
				Error: "The two passwords do not match",
			}
			err := tmpl.ExecuteTemplate(w, "layout", data)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		existingUser, err := getUserByUsername(username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if existingUser != nil {
			data := RegisterPageData{
				Error: "The username is already taken",
			}
			err := tmpl.ExecuteTemplate(w, "layout", data)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		err = addUser(username, email, fmt.Sprintf("%x", md5.Sum([]byte(password))))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	var user *User
	if r.Context().Value("user") != nil {
		user = r.Context().Value("user").(*User)
	}

	data := RegisterPageData{
		User: user,
	}

	err := tmpl.ExecuteTemplate(w, "layout", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	delete(session.Values, "user_id")

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/public", http.StatusFound)
}
