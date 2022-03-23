package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
)

var (
	regex            = regexp.MustCompile(`^([^\. ]+)\.([^\. ]+)$`)
	ErrInvalidFormat = fmt.Errorf("token err: invalid format")
)

type Token []byte

func NewToken(body []byte, secret string) Token {
	data := encodeToBase64(body)
	mac := computeHmac256(data, secret)
	return Token(data + "." + mac)
}

func (t Token) String() string {
	return string(t)
}

// does not check token's validity; use ValidateToken() instead
func (t Token) GetBody() ([]byte, error) {
	body, _, err := t.getSubmatch()
	if err != nil {
		return nil, ErrInvalidFormat
	}
	return decodeToBase64(body)
}

func (t Token) ValidateToken(key string) ([]byte, bool) {
	body, mac, err := t.getSubmatch()
	if err != nil {
		return nil, false
	}
	data, err := decodeToBase64(body)
	if err != nil {
		return nil, false
	}
	return data, hmac.Equal(mac, []byte(computeHmac256(body, key)))
}

// same as t.ValidateToken(key)
func ValidateToken(t Token, key string) ([]byte, bool) {
	return t.ValidateToken(key)
}

//SUBMATCH

func (t Token) getSubmatch() (string, []byte, error) {
	var sub = regex.FindSubmatch(t)
	if len(sub) != 3 {
		return "", nil, ErrInvalidFormat
	}
	return string(sub[1]), sub[2], nil
}

//BODY

func encodeToBase64(body []byte) string {
	/*var dst = make([]byte, base64.RawURLEncoding.EncodedLen(len(body)))
	base64.RawURLEncoding.Encode(dst, body)
	return dst*/
	return base64.RawURLEncoding.EncodeToString(body)
}

func decodeToBase64(enc string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(enc)
}

//HMAC

func computeHmac256(body string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
