package web

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func (app *App) NewRouter() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(app.authMiddleware)

	r.Get("/", app.TimelineHandler)
	r.Get("/public", app.PublicTimelineHandler)

	r.Get("/login", app.LoginHandler)
	r.Post("/login", app.LoginHandler)

	r.Get("/register", app.RegisterHandler)
	r.Post("/register", app.RegisterHandler)

	r.Get("/logout", app.LogoutHandler)

	r.Post("/add_message", app.AddMessageHandler)

	r.Get("/{username}/follow", app.FollowUserHandler)
	r.Get("/{username}/unfollow", app.UnfollowUserHandler)
	r.Get("/{username}", app.UserTimelineHandler)
	// API
	r.Get("/fllws/{username})", app.FollowersHandler)
	r.Post("/fllws/{username})", app.FollowUserAPIHandler)

	r.Get("/latest", app.LatestOperationHandler)
	r.Get("/msgs", app.GetMessagesHandler)
	r.Get("/msgs/{username}", app.GetUserMessagesHandler)

	r.Post("/msgs/{username}", app.PostUserMessageHandler)
	r.Post("/register", app.RegisterAPIHandler)

	r.Handle("/static/*", staicFileServer())

	return r
}

func staicFileServer() http.Handler {
	fs := http.FileServer(http.Dir("./static"))
	return http.StripPrefix("/static/", fs)
}
func (app *App) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := app.getSessionUserID(r)

		if userID > 0 {
			user, err := app.getUserById(userID)
			if err == nil && user != nil {
				ctx := context.WithValue(r.Context(), "user", user)
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (app *App) latestMiddleware(next http.Handler) http.Handler {
	return next
}

func (app *App) authorizationMiddleware(next http.Handler) http.Handler {
	return next
}
