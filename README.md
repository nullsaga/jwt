# JWT Implementation in Go
This library provides a simple and flexible way to create and verify JSON Web Tokens (JWT)
using various signing algorithms in Go. It supports the HS256, HS384, and HS512 signing algorithms.


## Installation
To use this library, simply import it into your Go project:

```go
go get github.com/yourusername/jwt-library
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

func main() {
	// Create a new HS256 signer
	token := jwt.New(jwt.NewHS256Signer(), []byte("longsecret"))
	
	// Create a JWT with custom claims
	jwToken, err := token.Make(map[string]any{
		"sub": "123",  // Subject
		"exp": time.Now().Add(10 * time.Second).Unix(), // Expiration time
	})

	if err != nil {
		fmt.Println(err)
		return
	}
	
	// Token verification
	claims, err := token.Verify(jwToken)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Verified Claims:", claims)
}
```
