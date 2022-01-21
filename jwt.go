package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/Amqp-prtcl/snowflakes"
)

var (
	regex            = regexp.MustCompile(`^([^\. ]+)\.([^\. ]+)$`)
	ErrInvalidFormat = fmt.Errorf("token err: invalid format")
)

type tokenBody struct {
	Id        snowflakes.ID `json:"id"`
	Timestamp int64         `json:"stamp"`
}

type Token []byte

func NewToken(id snowflakes.ID, timestamp int64, secret string) Token {
	body := getBodyFromId(id, timestamp)
	mac := ComputeHmac256(body, secret)
	return Token(body + "." + mac)
}

func (t Token) String() string {
	return string(t)
}

func (t Token) GetBody() (snowflakes.ID, int64, error) {
	body, _, err := t.getSubmatch()
	if err != nil {
		return 0, 0, ErrInvalidFormat
	}
	return getIdFromBody(body)
}

func (t Token) ValidateToken(key string) (snowflakes.ID, int64, bool) {
	body, mac, err := t.getSubmatch()
	if err != nil {
		fmt.Println("1")
		return 0, 0, false
	}
	id, timestamp, err := getIdFromBody(body)
	if err != nil {
		fmt.Println(err)
		return id, timestamp, false
	}
	fmt.Println("3")
	return id, timestamp, hmac.Equal(mac, []byte(ComputeHmac256(body, key)))
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

func getIdFromBody(body string) (snowflakes.ID, int64, error) {
	var tBody = tokenBody{}
	data, err := base64.RawURLEncoding.DecodeString(string(body))
	if err != nil {
		return 0, 0, err
	}
	err = json.Unmarshal(data, &tBody)
	return tBody.Id, tBody.Timestamp, err
}

func getBodyFromId(id snowflakes.ID, timestamp int64) string {
	var body = tokenBody{
		Id:        id,
		Timestamp: timestamp,
	}
	data, _ := json.Marshal(body)
	return base64.RawURLEncoding.EncodeToString(data)
}

//HMAC

func ComputeHmac256(body string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}