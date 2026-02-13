package web

import (
	"database/sql"
	"html/template"

	"github.com/gorilla/sessions"
)

type App struct {
	DB    *sql.DB
	Store *sessions.CookieStore
	Pages map[string]*template.Template
}
