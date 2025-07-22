package dbsc_proof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
)

// JWKToPublicKey converts JWK to crypto.PublicKey
func ParseJwk(jwk map[string]interface{}) (pubKey crypto.PublicKey, pem string, err error) {
	kty, ok := jwk["kty"].(string)
	if !ok {
		return nil, "", fmt.Errorf("missing or invalid kty")
	}

	switch kty {
	case "EC":
		pubKey, err = jwkToECDSAPublicKey(jwk)
	case "RSA":
		pubKey, err = jwkToRSAPublicKey(jwk)
	default:
		return nil, "", fmt.Errorf("unsupported key type: %s", kty)
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to convert JWK to public key: %w", err)
	}
	pem, err = PublicKeyToPEM(pubKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to convert public key to PEM: %w", err)
	}
	return pubKey, pem, nil
}

func jwkToECDSAPublicKey(jwk map[string]interface{}) (*ecdsa.PublicKey, error) {
	crv, ok := jwk["crv"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid crv")
	}

	x, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid x")
	}

	y, ok := jwk["y"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid y")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("invalid x coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		return nil, fmt.Errorf("invalid y coordinate: %w", err)
	}

	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	pub := ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	return &pub, nil
}

func jwkToRSAPublicKey(jwk map[string]interface{}) (*rsa.PublicKey, error) {
	n, ok := jwk["n"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid n")
	}

	e, ok := jwk["e"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid e")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, fmt.Errorf("invalid n: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return nil, fmt.Errorf("invalid e: %w", err)
	}

	// Convert bytes to big.Int
	var nInt, eInt big.Int
	nInt.SetBytes(nBytes)
	eInt.SetBytes(eBytes)

	return &rsa.PublicKey{
		N: &nInt,
		E: int(eInt.Int64()),
	}, nil
}

func PublicKeyToPEM(publicKey crypto.PublicKey) (string, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}
