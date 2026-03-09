package web

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

//User Mettrics
var PostsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "user_posts_total",
		Help: "The total posts recorded",
	})

var NewRegisteredUsers = promauto.NewCounter(prometheus.CounterOpts{
	Name: "new_registered_users",
	Help: "Total amount of registered users",
})

//HTTP Errors
var InternalServerErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "total_server_errors",
	Help: "Tracks Server Errors, and the Http Request that triggered it",
}, []string{"url", "method"})

var InvalidRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "total_invalid_request",
	Help: "The total amount of 400-codes thrown",
}, []string{"url", "error msg"})







