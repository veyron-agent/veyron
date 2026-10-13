package veyron

import (
	"flag"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/veyron-agent/veyron/internal/config"
	"github.com/veyron-agent/veyron/internal/handlers/auth"
	"github.com/veyron-agent/veyron/internal/store"
)

func main() {

	port := flag.String("port", ":9090", "port for server")

	flag.Parse()

	config.Init()

	// connect database
	store.ConnectDatabase()
	// create tables
	store.CreateTables()

	router := chi.NewRouter()

	router.Route("/api/v1", func(r chi.Router) {
		r.Post(
			"/register", auth.Register,
		)

		r.Post(
			"/login", auth.Login,
		)

		r.Post(
			"/refresh", auth.Refresh,
		)
	})

	http.ListenAndServe(*port, router)
}
