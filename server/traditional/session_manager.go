package traditional

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"dbsc-demo/logging"
)

type SessionManager struct {
	cookies map[string]*Cookie
}

type Cookie struct {
	Value     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		cookies: make(map[string]*Cookie),
	}
}

func (s *SessionManager) GenerateCookie() *Cookie {
	cookie := &Cookie{
		Value:     s.generateRandomID(),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	s.cookies[cookie.Value] = cookie
	logging.Logger.Printf("Generated traditional cookie: %s", cookie.Value)
	return cookie
}

func (s *SessionManager) VerifyCookie(value string) bool {
	cookie, exists := s.cookies[value]
	return exists && time.Now().Before(cookie.ExpiresAt)
}

func (s *SessionManager) generateRandomID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}
