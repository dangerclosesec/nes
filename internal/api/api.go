package api

import (
	"encoding/json"
	stdlog "log"
	"net/http"
	"os"

	"github.com/dangerclosesec/nes"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var (
	log = stdlog.New(os.Stdout, "\033[35;4;239m[ api    ]\033[0m ", stdlog.Lmicroseconds|stdlog.Lmsgprefix|stdlog.Ldate|stdlog.Lmicroseconds)
)

func Handler(m *nes.Manager) http.Handler {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(loggingMiddleware)

	// Routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/services", services(m))
	})

	return r
}

// loggingMiddleware adds custom request logging
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("API Request: %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func services(m *nes.Manager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		services := m.Config.Services

		if err := json.NewEncoder(w).Encode(services); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
