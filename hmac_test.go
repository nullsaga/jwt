package jwt

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestCanSignClaimAndVerify(t *testing.T) {
	secret := []byte("secret")
	signer := NewHS256Signer()
	expire := time.Now().Add(10 * time.Second).Unix()
	claims, _ := json.Marshal(map[string]any{
		"sub": "1",
		"exp": expire,
	})

	claimsEncoded := base64.RawURLEncoding.EncodeToString(claims)

	hash, err := signer.sign(claimsEncoded, secret)
	if err != nil {
		t.Errorf("sign() error: %v", err)
	}

	if len(hash) == 0 {
		t.Errorf("Expected a non-empty token, got an empty byte slice")
	}

	if !signer.verify(claimsEncoded, hash, secret) {
		t.Errorf("Signature verification failed")
	}
}
