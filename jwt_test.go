package jwt_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/Amqp-prtcl/jwt"
)

func Test(t *testing.T) {
	key := "secret"

	token := jwt.NewToken(47985943326, time.Now().Unix(), key)

	fmt.Printf("token: %s\n", token)

	id1, time1, ok := token.ValidateToken("secret1")
	fmt.Printf("(1) id: %v, time: %v, ok: %v\n", id1, time1, ok)

	id2, time2, ok := token.ValidateToken(key)
	fmt.Printf("(2) id: %v, time:%v, ok: %v\n", id2, time2, ok)
}
