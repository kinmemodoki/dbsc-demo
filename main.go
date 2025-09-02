package main

import (
	"dbsc-demo/logging"
	"fmt"
	"log"
	"net/http"
	"time"

	"dbsc-demo/server/dbsc"
	"dbsc-demo/server/traditional"

	"github.com/gorilla/mux"
)

func main() {
	traditionalServer := traditional.NewTraditionalServer()
	dbscServer := dbsc.NewDBSCServer()

	r := setupRouter(traditionalServer, dbscServer)

	fmt.Println("🚀 DBSC Demo Server starting on http://localhost:8080")
	fmt.Println("📖 DBSC specification: https://github.com/w3c/webappsec-dbsc")

	log.Fatal(http.ListenAndServe(":8080", r))
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		statusColor := getStatusColor(wrapped.statusCode)
		methodColor := "\033[36m" // cyan
		pathColor := "\033[37m"   // white
		resetColor := "\033[0m"   // reset

		fmt.Printf("%s[%s]%s %s%s%s %s%s%s - %v\n",
			statusColor, http.StatusText(wrapped.statusCode), resetColor,
			methodColor, r.Method, resetColor,
			pathColor, r.URL.Path, resetColor,
			duration,
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func getStatusColor(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "\033[32m" // green
	case statusCode >= 300 && statusCode < 400:
		return "\033[33m" // yellow
	case statusCode >= 400 && statusCode < 500:
		return "\033[31m" // red
	case statusCode >= 500:
		return "\033[35m" // magenta
	default:
		return "\033[37m" // white
	}
}

func setupRouter(traditionalServer *traditional.TraditionalServer, dbscServer *dbsc.DBSCServer) *mux.Router {
	logging.Logger.Println("Setting up router")
	r := mux.NewRouter()

	r.Use(loggingMiddleware)

	r.HandleFunc(traditional.EndpointHome, traditional.HomePageHandler)
	r.HandleFunc(traditional.EndpointLogin, traditional.LoginPageHandler).Methods("GET")
	r.HandleFunc(traditional.EndpointLogin, func(w http.ResponseWriter, r *http.Request) {
		dbscServer.InitRegistrationDBSCSessionMiddleware(http.HandlerFunc(traditionalServer.LoginHandler)).ServeHTTP(w, r)
	}).Methods("POST")
	r.HandleFunc(traditional.EndpointUserPage, func(w http.ResponseWriter, r *http.Request) {
		traditionalServer.VerifyCookieMiddleware(http.HandlerFunc(traditional.UserPageHandler)).ServeHTTP(w, r)
	})

	// endpoints for DBSC
	r.HandleFunc(dbsc.EndpointDBSCStart, func(w http.ResponseWriter, r *http.Request) {
		traditionalServer.VerifyCookieMiddleware(http.HandlerFunc(dbscServer.DBSCRegisterHandler)).ServeHTTP(w, r)
	})
	r.HandleFunc(dbsc.EndpointDBSCRefresh, dbscServer.DBSCRefreshHandler).Methods("POST")

	// api
	r.HandleFunc("/debug/check_dbsc_session", func(w http.ResponseWriter, r *http.Request) {
		dbscServer.VerifyDBSCSessionMiddleware(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}),
		).ServeHTTP(w, r)
	})
	r.HandleFunc("/api/check_dbsc_session", func(w http.ResponseWriter, r *http.Request) {
		dbscServer.VerifyDBSCSessionMiddleware(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}),
		).ServeHTTP(w, r)
	})

	return r
}
