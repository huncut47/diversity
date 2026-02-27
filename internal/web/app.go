package web

import (
	"html/template"

	"github.com/gorilla/sessions"
	"gorm.io/gorm"
)

type App struct {
	DB    *gorm.DB
	Store *sessions.CookieStore
	Pages map[string]*template.Template
	Latest int
}
