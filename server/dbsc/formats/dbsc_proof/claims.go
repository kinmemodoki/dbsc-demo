package dbsc_proof

import (
	"dbsc-demo/logging"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type DBSCProof struct {
	Audience      []string               `json:"aud"`                     // 必須: 送信先URL(単体でも配列にする)
	JTI           string                 `json:"jti"`                     // 必須: チャレンジ値
	IssuedAt      *jwt.NumericDate       `json:"iat"`                     // 必須: 発行時刻
	Key           map[string]interface{} `json:"key"`                     // 必須: JWK公開キー
	Authorization string                 `json:"authorization,omitempty"` // 条件付き: 認証情報
	Subject       string                 `json:"sub,omitempty"`           // リフレッシュ時必須: セッションID

	PublicKey interface{} `json:"-"` // JWKから変換された公開キー
	PEM       string      `json:"-"` // PEM形式の公開キー
}

func ParseDBSCProofPayload(claims map[string]interface{}) (*DBSCProof, error) {

	aud, ok := claims["aud"]
	if !ok {
		return nil, errors.New("invalid aud claim: missing")
	}
	// audは単一のURLまたはURLの配列であることを期待
	var audienceArr []string
	switch v := aud.(type) {
	case string:
		audienceArr = []string{v}
	case []string:
		audienceArr = v
	default:
		logging.Logger.Printf("aud params: %v", aud)
		return nil, fmt.Errorf("invalid aud claim: unexpected type(%T)", aud)
	}

	var jti string
	j, ok := claims["jti"]
	if !ok {
		return nil, errors.New("invalid jti claim: missing")
	}
	jti, ok = j.(string)
	if !ok {
		return nil, errors.New("invalid jti claim: unexpected type")
	}

	var issuedAt *jwt.NumericDate
	if iatVal, ok := claims["iat"]; ok {
		switch v := iatVal.(type) {
		case float64:
			issuedAt = jwt.NewNumericDate(time.Unix(int64(v), 0))
		case int64:
			issuedAt = jwt.NewNumericDate(time.Unix(v, 0))
		case int:
			issuedAt = jwt.NewNumericDate(time.Unix(int64(v), 0))
		case time.Time:
			issuedAt = jwt.NewNumericDate(v)
		default:
			return nil, fmt.Errorf("invalid iat claim: unexpected type(%T)", v)
		}
	} else {
		return nil, errors.New("invalid iat claim: missing")
	}

	var key map[string]interface{}
	k, ok := claims["key"]
	if !ok {
		return nil, errors.New("invalid key claim: missing")
	}
	key, ok = k.(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid key claim: unexpected type")
	}
	publicKey, pem, err := ParseJwk(key)
	if err != nil {
		return nil, errors.New("invalid key claim: " + err.Error())
	}

	var authorization string
	if auth, ok := claims["authorization"]; ok {
		authorization, ok = auth.(string)
		if !ok {
			return nil, errors.New("invalid authorization claim: unexpected type")
		}
	}

	var subject string
	if sub, ok := claims["sub"]; ok {
		subject, ok = sub.(string)
		if !ok {
			return nil, errors.New("invalid sub claim: unexpected type")
		}
	}

	parsedClaims := &DBSCProof{
		Audience:      audienceArr,
		JTI:           jti,
		IssuedAt:      issuedAt,
		Key:           key,
		Authorization: authorization,
		Subject:       subject,
		PublicKey:     publicKey,
		PEM:           pem,
	}

	return parsedClaims, nil
}
