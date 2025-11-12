package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Claim interface {
	Exp() int64
}

type Signer interface {
	sign(data string, secret []byte) ([]byte, error)
	verify(data string, signature []byte, secret []byte) bool
	Algorithm() string
}

type MapClaim map[string]any

type Token[T Claim] struct {
	secret []byte
	signer Signer
}

const (
	tokenType string = "JWT"
)

func New[T Claim](signer Signer, secret []byte) *Token[T] {
	return &Token[T]{secret: secret, signer: signer}
}

func (t *Token[T]) Make(claim T) (string, error) {
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

func (t *Token[T]) Verify(token string) (T, error) {
	var zero T
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return zero, errors.New("invalid token format")
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return zero, fmt.Errorf("unable to decode signature: %w", err)
	}

	if ok := t.signer.verify(fmt.Sprintf("%s.%s", parts[0], parts[1]), signature, t.secret); !ok {
		return zero, errors.New("signature verification failed")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return zero, fmt.Errorf("unable to decode claim: %w", err)
	}

	var payload T
	if err = json.Unmarshal(payloadJSON, &payload); err != nil {
		return zero, fmt.Errorf("invalid claim json: %w", err)
	}

	if time.Now().Unix() > payload.Exp() {
		return zero, errors.New("token has expired")
	}

	return payload, nil
}
