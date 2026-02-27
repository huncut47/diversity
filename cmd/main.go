package main

import (
	"html/template"
	"log"
	"log/slog"
	"minitwit/internal/models"
	"minitwit/internal/utils"
	"minitwit/internal/web"
	"net/http"

	"github.com/gorilla/sessions"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const DATABASE = "data/minitwit.db"

var db *gorm.DB

var store = sessions.NewCookieStore(
	[]byte("12345678901234567890123456789012"),
	[]byte("12345678901234567890123456789012"),
)
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

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal(err)
	}
	defer sqlDB.Close()

	err = db.AutoMigrate(&models.User{}, &models.Message{}, &models.Follower{})
        if err != nil {
                log.Fatal(err)
        }

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   false, // true only on HTTPS
		SameSite: http.SameSiteLaxMode,
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

func connectDb() (*gorm.DB, error) {
	return gorm.Open(sqlite.Open(DATABASE), &gorm.Config{})
}
