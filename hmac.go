package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

type HSSigner struct {
	algo     string
	hashFunc func() hash.Hash
}

func NewHS256Signer() *HSSigner {
	return &HSSigner{hashFunc: sha256.New, algo: "HS256"}
}

func NewHS512Signer() *HSSigner {
	return &HSSigner{hashFunc: sha512.New, algo: "HS512"}
}

func NewHS384Signer() *HSSigner {
	return &HSSigner{hashFunc: sha512.New384, algo: "HS384"}
}

func (h *HSSigner) Algorithm() string {
	return h.algo
}

func (h *HSSigner) sign(data string, secret []byte) ([]byte, error) {
	hm := hmac.New(h.hashFunc, secret)
	_, err := hm.Write([]byte(data))
	if err != nil {
		return nil, err
	}

	return hm.Sum(nil), nil
}

func (h *HSSigner) verify(data string, signature []byte, secret []byte) bool {
	expectedSig, err := h.sign(data, secret)
	if err != nil {
		return false
	}

	return hmac.Equal(expectedSig, signature)
}
