package web

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type contextKey string

const userContextKey contextKey = "user"

func (app *App) NewRouter() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(metricsMiddleware)
	r.Use(app.authMiddleware)

	r.Get("/", app.TimelineHandler)
	r.Get("/public", app.PublicTimelineHandler)

	r.Get("/login", app.LoginHandler)
	r.Post("/login", app.LoginHandler)

	r.Get("/register", app.RegisterHandler)

	r.Get("/logout", app.LogoutHandler)

	r.Post("/add_message", app.AddMessageHandler)

	r.Get("/{username}/follow", app.FollowUserHandler)
	r.Get("/{username}/unfollow", app.UnfollowUserHandler)
	r.Get("/{username}", app.UserTimelineHandler)

	r.Get("/health", app.HealthHandler)

	// API routes with auth
	r.Group(func(api chi.Router) {
		api.Use(app.latestMiddleware)
		api.Use(app.authorizationMiddleware)

		api.Get("/msgs", app.GetMessagesHandler)
		api.Get("/msgs/{username}", app.GetUserMessagesHandler)
		api.Post("/msgs/{username}", app.PostUserMessageHandler)
		api.Get("/fllws/{username}", app.FollowersHandler)
		api.Post("/fllws/{username}", app.FollowUserAPIHandler)
	})

	// API routes without auth
	r.Group(func(api chi.Router) {
		api.Use(app.latestMiddleware)

		api.Get("/latest", app.LatestOperationHandler)
		api.Post("/register", app.RegisterDispatcher)
	})

	r.Handle("/static/*", staicFileServer())
	r.Handle("/metrics", promhttp.Handler())

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
				ctx := context.WithValue(r.Context(), userContextKey, user)
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (app *App) latestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("latest")
		if val != "" {
			v, err := strconv.Atoi(val)
			if err == nil {
				app.Latest = v
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (app *App) authorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(403)
			_, err := w.Write([]byte(`{"status": 403, "error_msg": "You are not authorized to use this resource!"}`))
			if err != nil {
				app.Logger.Error("Failed to write response", "error", err)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}
