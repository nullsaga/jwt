package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Signer interface {
	sign(data string, secret []byte) ([]byte, error)
	verify(data string, signature []byte, secret []byte) bool
	Algorithm() string
}

type MapClaim map[string]any

type Token struct {
	secret []byte
	signer Signer
}

const (
	tokenType string = "JWT"
)

func New(signer Signer, secret []byte) *Token {
	return &Token{secret: secret, signer: signer}
}

func (t *Token) Make(claim MapClaim) (string, error) {
	headerJson, err := json.Marshal(map[string]string{
		"alg": t.signer.Algorithm(),
		"typ": tokenType,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	claimJson, err := json.Marshal(claim)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claim: %w", err)
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJson)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(claimJson)
	signature, err := t.signer.sign(fmt.Sprintf("%s.%s", headerEncoded, payloadEncoded), t.secret)

	if err != nil {
		return "", fmt.Errorf("failed to create signature: %s", err)
	}

	return fmt.Sprintf(
		"%s.%s.%s",
		headerEncoded,
		payloadEncoded,
		base64.RawURLEncoding.EncodeToString(signature),
	), nil
}

func (t *Token) Verify(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("unable to decode signature: %w", err)
	}

	if ok := t.signer.verify(fmt.Sprintf("%s.%s", parts[0], parts[1]), signature, t.secret); !ok {
		return nil, errors.New("signature verification failed")
	}

	payloadJson, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("unable to decode claim: %w", err)
	}

	var payload map[string]any
	err = json.Unmarshal(payloadJson, &payload)
	if err != nil {
		return nil, fmt.Errorf("invalid claim json: %w", err)
	}

	if exp, ok := payload["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return nil, errors.New("token has expired")
		}
	}

	return payload, nil
}
