package main

import (
	"database/sql"
	"html/template"
	"log"
	"log/slog"
	"minitwit/internal/utils"
	"minitwit/internal/web"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
)

const DATABASE = "./minitwit.db"

var db *sql.DB

var store = sessions.NewCookieStore([]byte("dev_key"))

var funcMap = template.FuncMap{
	"gravatar": utils.GravatarURL,
	"datetime": utils.FormatDate,
}

func loadTemplate(files ...string) *template.Template {
	return template.Must(template.New("").Funcs(funcMap).ParseFiles(files...))
}

var pages = map[string]*template.Template{
	"register": loadTemplate("templates/layout.html", "templates/register.html"),
	"login":    loadTemplate("templates/layout.html", "templates/login.html"),
	"timeline": loadTemplate("templates/layout.html", "templates/timeline.html"),
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

	app := &web.App{
		DB:    db,
		Store: store,
		Pages: pages,
	}

	r := app.NewRouter()

	slog.Info("Starting server on :3000")
	err = http.ListenAndServe(":3000", r)
	if err != nil {
		return
	}
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
