# jwt

Please Note that is implementation does NOT follow any RFCs and should not be use in any professional or serious projects.

## Installation

To use the jwt library simply run the following command inside your Go module
```
go get http://github.com/Amqp-prtcl/
```
## Usage

In this library, a jwt `Token` is a byte slice following this format:
```
{body}.{mac}
```
Where the body is a base64 Raw (without padding) URL encoding of any byte slice,
and the mac is a base64 Raw URL encoding of a hmac of the body using the sha256 hash algorithm.

### Use the token

To create a newToken you can do:
```go
var token = jwt.NewToken(body, secret)
```
or to create one from a byte slice:
```go
var token = jwt.Token(byteSlice)
```

You can then verify its integrity with:
```go
var body, ok = token.ValidateToken(secret)
// or
body, ok = jwt.ValidateToken(token, secret)
```
