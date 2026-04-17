package main

import (
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"minitwit/internal/models"
	"minitwit/internal/utils"
	"minitwit/internal/web"

	"gorm.io/driver/postgres"

	"github.com/gorilla/sessions"
	"gorm.io/gorm"
)

const DATABASE = "data/minitwit.db"

var db *gorm.DB

var store = sessions.NewCookieStore(
	[]byte(os.Getenv("SESSION_AUTH_KEY")),
	[]byte(os.Getenv("SESSION_ENCRYPTION_KEY")),
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
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	var err error
	db, err = connectDb()
	if err != nil {
		log.Fatal(err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		err := sqlDB.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	err = db.AutoMigrate(&models.User{}, &models.Message{}, &models.Follower{}, &models.AppState{})
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
		DB:     db,
		Store:  store,
		Pages:  pages,
		Logger: logger,
	}

	r := app.NewRouter()

	logger.Info("Starting server on :3000")
	err = http.ListenAndServe(":3000", r)
	if err != nil {
		return
	}
}

func connectDb() (*gorm.DB, error) {
	dsn := "host=database user=" + os.Getenv("POSTGRES_USER") + " password=" + os.Getenv("POSTGRES_PASSWORD") + " dbname=" + os.Getenv("POSTGRES_DB") + " port=5432 sslmode=disable TimeZone=UTC"
	for range 10 {
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err == nil {
			return db, nil
		}
		log.Println("DB not ready, retrying in 3s...")
		time.Sleep(3 * time.Second)
	}
	return gorm.Open(postgres.Open(dsn), &gorm.Config{})
}
