package formats

import (
	"fmt"
	"strings"
)

// Secure-Session-Registration ヘッダーのパラメータ
type SecureSessionRegistrationParams struct {
	Path          string // 必須: 登録エンドポイントのパス
	Challenge     string // オプション: チャレンジ値
	Authorization string // オプション: 認証情報
	ProviderKey   string // オプション: プロバイダー公開キー
	ProviderID    string // オプション: プロバイダーセッションID
	ProviderURL   string // オプション: プロバイダーURL
}

// アルゴリズムリストとパラメータの組み合わせ
type SecureSessionRegistrationEntry struct {
	Algorithms []string // ES256, RS256
	Params     *SecureSessionRegistrationParams
}

type SecureSessionRegistrationHeader []*SecureSessionRegistrationEntry

// ToSFV converts to HTTP header string
func (e *SecureSessionRegistrationEntry) ToSFV() string {
	// アルゴリズムリストを構築 (ES256 RS256)
	algList := "(" + strings.Join(e.Algorithms, " ") + ")"

	// パラメータを構築
	var params []string

	// path は必須
	params = append(params, fmt.Sprintf(`path="%s"`, e.Params.Path))

	if e.Params.Challenge != "" {
		params = append(params, fmt.Sprintf(`challenge="%s"`, e.Params.Challenge))
	}
	if e.Params.Authorization != "" {
		params = append(params, fmt.Sprintf(`authorization="%s"`, e.Params.Authorization))
	}
	if e.Params.ProviderKey != "" {
		params = append(params, fmt.Sprintf(`provider_key="%s"`, e.Params.ProviderKey))
	}
	if e.Params.ProviderID != "" {
		params = append(params, fmt.Sprintf(`provider_id="%s"`, e.Params.ProviderID))
	}
	if e.Params.ProviderURL != "" {
		params = append(params, fmt.Sprintf(`provider_url="%s"`, e.Params.ProviderURL))
	}

	return algList + "; " + strings.Join(params, "; ")
}
