package formats

import (
	"fmt"
	"strings"
)

// 単一のチャレンジ
type SecureSessionChallenge struct {
	Challenge string // チャレンジ値
	ID        string // オプション: セッションID
}

// ヘッダー（リスト構造）
type SecureSessionChallengeHeader []SecureSessionChallenge

// ToSFV converts to HTTP header string
func (h SecureSessionChallengeHeader) ToSFV() string {
	var entries []string

	for _, challenge := range h {
		entry := fmt.Sprintf(`"%s"`, challenge.Challenge)

		if challenge.ID != "" {
			entry += fmt.Sprintf(`;id="%s"`, challenge.ID)
		}

		entries = append(entries, entry)
	}

	return strings.Join(entries, ", ")
}

// CreateSingle creates a single challenge header
func NewSecureSessionChallengeHeader(challenge, sessionID string) SecureSessionChallengeHeader {
	return SecureSessionChallengeHeader{
		{
			Challenge: challenge,
			ID:        sessionID,
		},
	}
}
