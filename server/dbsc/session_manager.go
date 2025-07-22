package dbsc

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"dbsc-demo/logging"
)

type DBSCSessionManager struct {
	cookies    map[string]*DBSCCookie
	challenges map[string]*DBSCChallenge
	sessions   map[string]*DBSCSession
}

func NewDBSCSessionManager() *DBSCSessionManager {
	return &DBSCSessionManager{
		cookies:    make(map[string]*DBSCCookie),
		challenges: make(map[string]*DBSCChallenge),
		sessions:   make(map[string]*DBSCSession),
	}
}

type DBSCChallenge struct {
	Value     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (s *DBSCSessionManager) GenerateChallenge() string {
	challenge := &DBSCChallenge{
		Value:     s.generateRandomID(),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Minute),
	}
	s.challenges[challenge.Value] = challenge
	return challenge.Value
}

func (s *DBSCSessionManager) VerifyChallenge(value string) bool {
	challenge, exists := s.challenges[value]
	return exists && time.Now().Before(challenge.ExpiresAt)
}

type DBSCCookie struct {
	Value     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (s *DBSCSessionManager) GenerateCookie() *DBSCCookie {
	cookie := &DBSCCookie{
		Value:     s.generateRandomID(),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Second),
	}
	s.cookies[cookie.Value] = cookie
	return cookie
}

func (s *DBSCSessionManager) VerifyCookie(value string) bool {
	cookie, exists := s.cookies[value]
	return exists && time.Now().Before(cookie.ExpiresAt)
}

type DBSCSession struct {
	Identifier   string
	PublicKeyPEM string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

func (s *DBSCSessionManager) GenerateSession(pem string) *DBSCSession {
	session := &DBSCSession{
		Identifier:   s.generateRandomID(),
		PublicKeyPEM: pem,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour), // 30 days expiration
	}
	s.sessions[session.Identifier] = session
	logging.Logger.Printf("Generated new session with ID: %s", session.Identifier)
	return session
}

func (s *DBSCSessionManager) VerifySession(identifier string, pem string) bool {
	session, exists := s.sessions[identifier]
	return exists && time.Now().Before(session.ExpiresAt) && session.PublicKeyPEM == pem
}

func (s *DBSCSessionManager) IsExistSession(identifier string) bool {
	session, exists := s.sessions[identifier]
	return exists && time.Now().Before(session.ExpiresAt)
}

func (s *DBSCSessionManager) generateRandomID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}
