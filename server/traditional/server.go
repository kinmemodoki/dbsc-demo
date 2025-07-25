package traditional

import (
	"dbsc-demo/logging"
	"net/http"
)

const (
	EndpointHome     = "/"
	EndpointLogin    = "/login"
	EndpointUserPage = "/userpage"
)

type TraditionalServer struct {
	sessionManager *SessionManager
}

func NewTraditionalServer() *TraditionalServer {
	return &TraditionalServer{
		sessionManager: NewSessionManager(),
	}
}

func LoginPageHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/login.html")
}

func UserPageHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/userpage.html")

}

func (s *TraditionalServer) LoginHandler(w http.ResponseWriter, r *http.Request) {
	logging.Logger.Println("Attempting to log in")

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}

	if username != "test" || password != "test" {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	sessionID := s.sessionManager.GenerateCookie().Value

	http.SetCookie(w, &http.Cookie{
		Name:     "traditional_cookie",
		Value:    sessionID,
		SameSite: http.SameSiteLaxMode,
		// MaxAge: 3600,
	})

	w.Header().Set("Content-Type", "text/plain;charset=utf-8")
	w.WriteHeader(http.StatusNoContent)
	// http.Redirect(w, r, EndpointHome, http.StatusSeeOther)
}

func (s *TraditionalServer) VerifyCookieMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logging.Logger.Println("Verifying traditional session")
		cookie, err := r.Cookie("traditional_cookie")
		if err != nil || cookie == nil {
			http.Error(w, "Session cookie not found", http.StatusUnauthorized)
			w.Header().Set("Location", EndpointLogin)
			return
		}

		if !s.sessionManager.VerifyCookie(cookie.Value) {
			http.Error(w, "Invalid session cookie", http.StatusUnauthorized)
			w.Header().Set("Location", EndpointLogin)
			return
		}

		next.ServeHTTP(w, r)
	})
}
