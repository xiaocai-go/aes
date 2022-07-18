# AES Encryption Tool

## Installation
1. You can use the below Go command to install AES encryption tool.

```sh
$ go get -u github.com/xiaocai-go/aes
```

2. Import it in your code:

```go
import "github.com/xiaocai-go/aes"
```

## Quick start
```go
package main

import (
	"fmt"
	"github.com/xiaocai-go/aes"
)

func main() {
	tool := aes.New(aes.NewOptions([]byte("1234567812345678"), []byte("1234567812345678")))

	// 加密
	fmt.Println(tool.Encrypt("this is content")) // wAlMQOHzn0Iy5mBuul7ShA== <nil>

	// 解密
	fmt.Println(tool.Decrypt("wAlMQOHzn0Iy5mBuul7ShA==")) // this is content <nil>
}
```