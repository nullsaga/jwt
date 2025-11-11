# JWT Implementation in Go
This library provides a simple and flexible way to create and verify JSON Web Tokens (JWT)
using various signing algorithms in Go. It supports the HS256, HS384, and HS512 signing algorithms.


## Installation
To use this library, simply import it into your Go project:

```go
go get github.com/nullsaga/jwt
```

## Example usage
To create a JWT token, use the Make method with your desired claims. Here’s an example of creating
a JWT with an expiration time:
```go
package main

import (
	"fmt"
	"time"

	"github.com/staticless/jwt"
)

// Define a custom claim type implementing jwt.Claim
type MyClaim struct {
	Sub    string `json:"sub"`
	Expire int64  `json:"exp"`
}

// Exp method required by jwt.Claim
func (c *MyClaim) Exp() int64 {
	return c.Expire
}

func main() {
	token := jwt.New[*MyClaim](jwt.NewHS256Signer(), []byte("longsecret"))
	
	claim := &MyClaim{
		Sub:    "123",
		Expire: time.Now().Add(10 * time.Second).Unix(),
	}

	jwToken, err := token.Make(claim)
	if err != nil {
		fmt.Println("Error creating token:", err)
		return
	}

	fmt.Println("Generated Token:", jwToken)
	
	verifiedClaim, err := token.Verify(jwToken)
	if err != nil {
		fmt.Println("Error verifying token:", err)
		return
	}

	fmt.Printf("Verified Claims: %+v\n", verifiedClaim)
}
```
