package main

import (
	"context"
	"crypto/md5"
	"database/sql"
	"fmt"
	"log"
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

var store = sessions.NewCookieStore([]byte("dev_key"))

type User struct {
	UserID int
	Username string
	Email string
	PwHash string
}

func main() {
	var err error
	db, err = connectDb()
	if err != nil {
        log.Fatal(err)
    }
	defer db.Close()

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})
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

func getUserId(username string) (int, error){
	var id int
	err := db.QueryRow("select user_id from user where username = ?", username).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}

func getUserById(userID int) (*User, error) {
	u := &User{}
	err := db.QueryRow("select user_id, username, email, pw_hash from user where user_id = ?", userID).Scan(&u.UserID, &u.Username, &u.Email, &u.PwHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u ,err
}

func getUserByUsername(username string) (*User, error) {
	u := &User{}
	err := db.QueryRow("select user_id, username, email, pw_hash from user where username = ?", username).Scan(&u.UserID, &u.Username, &u.Email, &u.PwHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u ,err
}

func getSessionUserID(r *http.Request) int {
	session, _ := store.Get(r, "session")
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