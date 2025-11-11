package jwt

import (
	"testing"
	"time"
)

type TestClaim struct {
	Sub    string `json:"sub"`
	Expire int64  `json:"exp"`
}

func (c *TestClaim) Exp() int64 {
	return c.Expire
}

func TestTokenMakeAndVerify(t *testing.T) {
	secret := []byte("supersecret")
	signer := NewHS256Signer()

	token := New[*TestClaim](signer, secret)

	claim := &TestClaim{
		Sub:    "user123",
		Expire: time.Now().Add(1 * time.Minute).Unix(),
	}

	jwtString, err := token.Make(claim)
	if err != nil {
		t.Fatalf("Make failed: %v", err)
	}

	if jwtString == "" {
		t.Fatal("Make returned empty JWT")
	}

	verifiedClaim, err := token.Verify(jwtString)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if verifiedClaim.Sub != claim.Sub {
		t.Errorf("Expected Sub '%s', got '%s'", claim.Sub, verifiedClaim.Sub)
	}

	if verifiedClaim.Expire != claim.Expire {
		t.Errorf("Expected Expire '%d', got '%d'", claim.Expire, verifiedClaim.Expire)
	}
}

func TestTokenExpired(t *testing.T) {
	secret := []byte("supersecret")
	signer := NewHS256Signer()
	token := New[*TestClaim](signer, secret)

	claim := &TestClaim{
		Sub:    "user123",
		Expire: time.Now().Add(-1 * time.Minute).Unix(),
	}

	jwtString, err := token.Make(claim)
	if err != nil {
		t.Fatalf("Make failed: %v", err)
	}

	_, err = token.Verify(jwtString)
	if err == nil {
		t.Fatal("Expected error for expired token, got nil")
	}
}
