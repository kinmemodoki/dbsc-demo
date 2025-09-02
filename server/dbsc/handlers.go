package dbsc

import (
	"encoding/json"
	"fmt"
	"net/http"

	"dbsc-demo/logging"
	"dbsc-demo/server/dbsc/formats"
	"dbsc-demo/server/dbsc/formats/dbsc_proof"
)

type DBSCServer struct {
	DBSCSessionManager *DBSCSessionManager
	DBSCProofVerifier  *dbsc_proof.DBSCProofVerifier
}

const (
	EndpointDBSCStart   = "/dbsc_start"
	EndpointDBSCRefresh = "/dbsc_refresh"
)

func NewDBSCServer() *DBSCServer {
	sessionManager := NewDBSCSessionManager()
	return &DBSCServer{
		DBSCSessionManager: sessionManager,
		DBSCProofVerifier:  dbsc_proof.NewDBSCProofVerifier(sessionManager),
	}
}

func (s *DBSCServer) InitRegistrationDBSCSessionMiddleware(next http.Handler) http.Handler {
	logging.Logger.Printf("==== Initializing DBSC session registration middleware ====")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		type statusWriter struct {
			http.ResponseWriter
			status int
		}

		sw := &statusWriter{ResponseWriter: w, status: 200}

		logging.Logger.Printf("Sending DBSC session registration challenge")
		secureSessionRegistration := &formats.SecureSessionRegistrationEntry{
			Algorithms: []string{"ES256", "RS256"},
			Params: &formats.SecureSessionRegistrationParams{
				Path:      EndpointDBSCStart,
				Challenge: s.DBSCSessionManager.GenerateChallenge(),
			},
		}
		w.Header().Set("Sec-Session-Registration", secureSessionRegistration.ToSFV())

		next.ServeHTTP(sw, r)
	})
}

func (s *DBSCServer) DBSCRegisterHandler(w http.ResponseWriter, r *http.Request) {
	logging.Logger.Printf("==== DBSC Registration Handler ====")
	secureSessionResponse := r.Header.Get("Sec-Session-Response")
	if secureSessionResponse == "" {
		logging.Logger.Println("Secure-Session-Response header required")
		http.Error(w, "Secure-Session-Response header required", http.StatusBadRequest)
		return
	}

	logging.Logger.Printf("Received DBSC registration request with proof: %s", secureSessionResponse)

	dbscProof, err := s.DBSCProofVerifier.VerifyDBSCProof(secureSessionResponse, s.getOrigin(r)+EndpointDBSCStart)
	if err != nil {
		logging.Logger.Printf("Failed to verify DBSC proof: %v", err)
		http.Error(w, fmt.Sprintf("Invalid DBSC proof: %v", err), http.StatusBadRequest)
		return
	}

	logging.Logger.Printf("Successfully verified DBSC proof for registration")

	session := s.DBSCSessionManager.GenerateSession(dbscProof.PEM)
	logging.Logger.Printf("Generated new session with ID: %s", session.Identifier)

	cookie := s.DBSCSessionManager.GenerateCookie()

	response := formats.SessionInstructionResponse{
		Continue:          true,
		SessionIdentifier: session.Identifier,
		RefreshURL:        EndpointDBSCRefresh,
		Scope: formats.SessionInstructionScope{
			Origin:      "https://localhost:8080",
			IncludeSite: true,
		},
		Credentials: []formats.SessionInstructionCredential{
			{
				Type:       "cookie",
				Name:       "dbsc_cookie",
				Attributes: "SameSite=Lax",
			},
		},
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "dbsc_cookie",
		Value:    cookie.Value,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   10,
	})

	logging.Logger.Printf("Sending session instruction response: %+v", response)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *DBSCServer) VerifyDBSCSessionMiddleware(next http.Handler) http.Handler {
	logging.Logger.Printf("==== Verifying DBSC session ====")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("dbsc_cookie")
		if err != nil || cookie == nil {
			http.Error(w, "DBSC session cookie not found", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *DBSCServer) DBSCRefreshHandler(w http.ResponseWriter, r *http.Request) {
	secureSessionId := r.Header.Get("Sec-Session-Id")
	secureSessionResponse := r.Header.Get("Sec-Session-Response")
	if secureSessionResponse == "" {
		// If no Sec-Session-Response header, issue a new challenge
		s.dbscRefreshChallengeHandler(w, r, secureSessionId)
		return
	}

	// If Sec-Session-Response header is present, verify and refresh the session
	s.dbscRefreshHandler(w, r, secureSessionResponse, secureSessionId)
}

func (s *DBSCServer) dbscRefreshChallengeHandler(w http.ResponseWriter, r *http.Request, sessionID string) {
	logging.Logger.Printf("==== DBSC Refresh(Challenge) Handler ====")

	if !s.DBSCSessionManager.IsExistSession(sessionID) {
		logging.Logger.Printf("DBSC session not found or expired")
		http.Error(w, "DBSC session not found or expired", http.StatusUnauthorized)
		return
	}

	challenge := s.DBSCSessionManager.GenerateChallenge()
	secureSessionChallengeHeader := formats.NewSecureSessionChallengeHeader(challenge, sessionID)
	w.Header().Set("Sec-Session-Challenge", secureSessionChallengeHeader.ToSFV())

	logging.Logger.Printf("Issuing DBSC session challenge: %s", w.Header().Values("Sec-Session-Challenge")[0])
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func (s *DBSCServer) dbscRefreshHandler(w http.ResponseWriter, r *http.Request, sessionResponse, sessionID string) {
	logging.Logger.Printf("==== DBSC Refresh Handler ====")
	dbscProof, err := s.DBSCProofVerifier.VerifyRefreshProof(sessionResponse, s.getOrigin(r)+EndpointDBSCRefresh, sessionID)
	if err != nil {
		logging.Logger.Printf("Failed to verify DBSC refresh proof: %v", err)
		http.Error(w, fmt.Sprintf("Invalid DBSC proof: %v", err), http.StatusBadRequest)
		return
	}

	cookie := s.DBSCSessionManager.GenerateCookie()

	var cookieAttributes string
	if r.TLS != nil {
		cookieAttributes = "HttpOnly; Secure; SameSite=Lax"
	} else {
		cookieAttributes = "HttpOnly; SameSite=Lax"
	}

	response := formats.SessionInstructionResponse{
		Continue:          true,
		SessionIdentifier: dbscProof.Subject,
		RefreshURL:        s.getOrigin(r) + EndpointDBSCRefresh,
		Scope: formats.SessionInstructionScope{
			Origin:      s.getOrigin(r),
			IncludeSite: true,
		},
		Credentials: []formats.SessionInstructionCredential{
			{
				Type:       "cookie",
				Name:       "dbsc_cookie",
				Attributes: cookieAttributes,
			},
		},
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "dbsc_cookie",
		Value:    cookie.Value,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteNoneMode,
		MaxAge:   60,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *DBSCServer) getOrigin(r *http.Request) string {
	origin := r.Header.Get("Origin")
	if origin == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		origin = fmt.Sprintf("%s://%s", scheme, r.Host)
	}
	return origin
}
