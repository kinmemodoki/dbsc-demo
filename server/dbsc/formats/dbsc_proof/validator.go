package dbsc_proof

import (
	"context"
	"fmt"

	"dbsc-demo/logging"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type DBSCProofVerifier struct {
	sessionManager SessionManager
}

type SessionManager interface {
	VerifyChallenge(value string) bool
	VerifySession(identifier string, pubKeyPEM string) bool
}

func NewDBSCProofVerifier(sessionManager SessionManager) *DBSCProofVerifier {
	return &DBSCProofVerifier{
		sessionManager: sessionManager,
	}
}

// VerifyDBSCProof verifies a DBSC Proof JWT using lestrrat-go/jwx
func (v *DBSCProofVerifier) VerifyDBSCProof(tokenString, expectedAud string) (*DBSCProof, error) {
	// Parse JWS message to extract header and payload without verification
	msg, err := jws.Parse([]byte(tokenString))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	if len(msg.Signatures()) == 0 {
		return nil, fmt.Errorf("no signatures found")
	}

	sig := msg.Signatures()[0]
	headers := sig.ProtectedHeaders()

	// Verify header
	if err := v.verifyJWSHeader(headers); err != nil {
		return nil, fmt.Errorf("header validation failed: %w", err)
	}

	// Parse payload as JWT to get claims
	token, err := jwt.Parse(msg.Payload(), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT payload: %w", err)
	}

	// Convert to map for our existing parsing logic
	claimsMap, err := token.AsMap(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to convert claims to map: %w", err)
	}

	// Parse DBSC-specific claims
	claims, err := ParseDBSCProofPayload(claimsMap)
	if err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Verify signature using the public key from claims
	if _, err := jws.Verify([]byte(tokenString), jws.WithKey(headers.Algorithm(), claims.PublicKey)); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Verify DBSC-specific requirements
	if err := v.verifyDBSCClaims(claims, expectedAud); err != nil {
		logging.Logger.Printf("DBSC claims validation failed: %v", err)
		return nil, fmt.Errorf("DBSC validation failed: %w", err)
	}

	return claims, nil
}

// verifyJWSHeader verifies JWS header for DBSC requirements
func (v *DBSCProofVerifier) verifyJWSHeader(headers jws.Headers) error {
	// Verify typ header
	typ := headers.Type()
	if typ != "dbsc+jwt" {
		return fmt.Errorf("invalid typ header: expected 'dbsc+jwt', got '%s'", typ)
	}

	// Verify algorithm
	alg := headers.Algorithm()
	if alg.String() != "ES256" && alg.String() != "RS256" {
		return fmt.Errorf("unsupported algorithm: %s", alg.String())
	}

	return nil
}

// verifyDBSCClaims verifies DBSC-specific claims
func (v *DBSCProofVerifier) verifyDBSCClaims(claims *DBSCProof, expectedAud string) error {
	// Verify audience
	correctAud := false
	for _, aud := range claims.Audience {
		if aud == expectedAud {
			correctAud = true
			break
		}
	}
	if !correctAud {
		return fmt.Errorf("invalid audience: expected '%s', got '%s'", expectedAud, claims.Audience)
	}

	// Verify challenge
	if claims.JTI == "" {
		return fmt.Errorf("missing jti (challenge)")
	}

	if !v.sessionManager.VerifyChallenge(claims.JTI) {
		logging.Logger.Printf("Invalid challenge: %s", claims.JTI)
		return fmt.Errorf("invalid challenge: %s", claims.JTI)
	}

	// Verify issued at time
	if claims.IssuedAt == nil {
		return fmt.Errorf("missing iat")
	}

	// Verify public key exists
	if len(claims.Key) == 0 {
		return fmt.Errorf("missing public key")
	}

	return nil
}

// VerifyRefreshProof verifies a refresh request with session ID validation
func (v *DBSCProofVerifier) VerifyRefreshProof(tokenString, expectedAud, sessionID string) (*DBSCProof, error) {
	claims, err := v.VerifyDBSCProof(tokenString, expectedAud)
	if err != nil {
		return nil, err
	}

	// Verify subject (session ID) for refresh requests
	/*
		If the DBSC proof is for a refresh request, the following claim MUST be present:
		- sub: a string specifying the session identifier.
		if claims.Subject == "" {
			return nil, fmt.Errorf("missing sub (session ID) for refresh request")
		}
	*/

	// Verify the public key matches the session's registered key
	if !v.sessionManager.VerifySession(sessionID, claims.PEM) {
		logging.Logger.Printf("Public key does not match session for session ID: %s", sessionID)
		return nil, fmt.Errorf("public key does not match session")
	}

	return claims, nil
}
