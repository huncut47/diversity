package web

import (
	"html/template"
	"log/slog"

	"github.com/gorilla/sessions"
	"gorm.io/gorm"
)

type App struct {
	Logger *slog.Logger
	DB     *gorm.DB
	Store  *sessions.CookieStore
	Pages  map[string]*template.Template
}
