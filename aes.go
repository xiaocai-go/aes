package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

var UnknownMode = errors.New("unknown mode")                // 加密模式错误
var UnknownPadding = errors.New("unknown padding way")      // 未知填充方式错误
var UnknownOutput = errors.New("unknown output way")        // 输出格式错误
var BlockUnPaddingErr = errors.New("block unPadding error") // 数据块填充错误
var BlockLenErr = errors.New("data block length error")     // 数据块长度错误

type Mode int8    // 加密模式
type Padding int8 // 填充方式
type Output int8  // 输出格式

const (
	ECBMode Mode = iota // 该模式无需偏移量IV
	CBCMode
	CTRMode
	OFBMode
	CFBMode
)

const (
	PKCS5Padding Padding = iota
	PKCS7Padding
)

const (
	Base64Output Output = iota
	HexOutput
)

// Options 配置项
type Options struct {
	Mode           // 加密模式
	Padding        // 填充方式
	Output         // 输出格式
	Key     []byte // 加密秘钥，支持128、192、256 bit（即长度为：16、24、32）
	IV      []byte // 自定义初始化偏移量，需要与区块（AES区块长度固定 128 bit）长度一致：16
}

type ecb struct {
	b         cipher.Block
	blockSize int
}

func (e *ecb) BlockSize() int {
	return e.blockSize
}

func (e *ecb) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		e.b.Encrypt(dst, src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
}

func (e *ecb) DecryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		e.b.Decrypt(dst, src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
}

// NewOptions 创建默认配置项
func NewOptions(key, iv []byte) *Options {
	return &Options{
		Mode:    CBCMode,
		Padding: PKCS7Padding,
		Output:  Base64Output,
		Key:     key,
		IV:      iv,
	}
}

type AES struct {
	options *Options
}

func New(options *Options) *AES {
	return &AES{options: options}
}

func (a *AES) Encrypt(data string) (s string, err error) {
	// block
	block, err := aes.NewCipher(a.options.Key)
	if err != nil {
		return
	}
	// 块填充
	paddingData, err := padding(a.options.Padding, []byte(data))
	if err != nil {
		return
	}
	// 填充长度校验
	if len(paddingData)%aes.BlockSize != 0 {
		return "", BlockLenErr
	}
	// 加密模式
	switch a.options.Mode {
	case ECBMode:
		return ecbEncrypt(block, paddingData, a.options.Output)
	case CBCMode:
		return cbcEncrypt(block, paddingData, a.options.IV, a.options.Output)
	case CTRMode:
		return ctrEncrypt(block, paddingData, a.options.IV, a.options.Output)
	case OFBMode:
		return ofbEncrypt(block, paddingData, a.options.IV, a.options.Output)
	case CFBMode:
		return cfbEncrypt(block, paddingData, a.options.IV, a.options.Output)
	default:
		return "", UnknownMode
	}
}

func (a *AES) Decrypt(data string) (s string, err error) {
	// block
	block, err := aes.NewCipher(a.options.Key)
	if err != nil {
		return
	}
	// 解析密文
	ciphertext, err := parseCiphertext(data, a.options.Output)
	if err != nil {
		return
	}
	// 密文长度校验
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", BlockLenErr
	}
	// 解密模式
	switch a.options.Mode {
	case ECBMode:
		return ecbDecrypt(block, ciphertext)
	case CBCMode:
		return cbcDecrypt(block, ciphertext, a.options.IV)
	case CTRMode:
		return ctrDecrypt(block, ciphertext, a.options.IV)
	case OFBMode:
		return ofbDecrypt(block, ciphertext, a.options.IV)
	case CFBMode:
		return cfbDecrypt(block, ciphertext, a.options.IV)
	default:
		return "", UnknownMode
	}
}

// padding 数据块填充
func padding(way Padding, data []byte) ([]byte, error) {
	switch way {
	case PKCS5Padding:
		return pkcs5Padding(data, aes.BlockSize), nil
	case PKCS7Padding:
		return pkcs7Padding(data, aes.BlockSize), nil
	default:
		return nil, UnknownPadding
	}
}

// unPadding 数据块取消填充
func unPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return data, nil
	}
	paddingNum := int(data[length-1])
	if length-paddingNum <= 0 {
		return nil, BlockUnPaddingErr
	}
	return data[:(length - paddingNum)], nil
}

// pkcs5Padding
func pkcs5Padding(data []byte, blockSize int) []byte {
	return pkcs7Padding(data, blockSize)
}

// pkcs7Padding
func pkcs7Padding(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(pad)}, pad)
	return append(data, padText...)
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

// ecbEncrypt ECB加密模式
func ecbEncrypt(block cipher.Block, paddingData []byte, output Output) (string, error) {
	// 加密模式
	blockMode := newECB(block)
	// 密文切片
	ciphertext := make([]byte, len(paddingData))
	// 加密
	blockMode.CryptBlocks(ciphertext, paddingData)
	// 输出
	return encryptOutput(output, ciphertext)
}

// cbcEncrypt CBC加密模式
func cbcEncrypt(block cipher.Block, paddingData []byte, iv []byte, output Output) (string, error) {
	// 加密模式
	blockMode := cipher.NewCBCEncrypter(block, iv)
	// 密文切片
	ciphertext := make([]byte, len(paddingData))
	// 加密
	blockMode.CryptBlocks(ciphertext, paddingData)
	// 输出
	return encryptOutput(output, ciphertext)
}

// ctrEncrypt CTR加密模式
func ctrEncrypt(block cipher.Block, paddingData []byte, iv []byte, output Output) (string, error) {
	// 加密模式
	blockMode := cipher.NewCTR(block, iv)
	// 密文切片
	ciphertext := make([]byte, len(paddingData))
	// 加密
	blockMode.XORKeyStream(ciphertext, paddingData)
	// 输出
	return encryptOutput(output, ciphertext)
}

// ofbEncrypt OFB加密模式
func ofbEncrypt(block cipher.Block, paddingData []byte, iv []byte, output Output) (string, error) {
	// 加密模式
	blockMode := cipher.NewOFB(block, iv)
	// 密文切片
	ciphertext := make([]byte, len(paddingData))
	// 加密
	blockMode.XORKeyStream(ciphertext, paddingData)
	// 输出
	return encryptOutput(output, ciphertext)
}

// cfbEncrypt CFB加密模式
func cfbEncrypt(block cipher.Block, paddingData []byte, iv []byte, output Output) (string, error) {
	// 加密模式
	blockMode := cipher.NewCFBEncrypter(block, iv)
	// 密文切片
	ciphertext := make([]byte, len(paddingData))
	// 加密
	blockMode.XORKeyStream(ciphertext, paddingData)
	// 输出
	return encryptOutput(output, ciphertext)
}

// ecbDecrypt ECB模式
func ecbDecrypt(block cipher.Block, ciphertext []byte) (string, error) {
	// 模式
	blockMode := newECB(block)
	// 创建数组
	plaintext := make([]byte, len(ciphertext))
	// 解密
	blockMode.DecryptBlocks(plaintext, ciphertext)
	// 输出
	return decryptOutput(plaintext)
}

// cbcDecrypt CBC模式
func cbcDecrypt(block cipher.Block, ciphertext []byte, iv []byte) (string, error) {
	// 模式
	blockMode := cipher.NewCBCDecrypter(block, iv)
	// 创建数组
	plaintext := make([]byte, len(ciphertext))
	// 解密
	blockMode.CryptBlocks(plaintext, ciphertext)
	// 输出
	return decryptOutput(plaintext)
}

// ctrDecrypt CTR模式
func ctrDecrypt(block cipher.Block, ciphertext []byte, iv []byte) (string, error) {
	// 模式
	blockMode := cipher.NewCTR(block, iv)
	// 创建数组
	plaintext := make([]byte, len(ciphertext))
	// 解密
	blockMode.XORKeyStream(plaintext, ciphertext)
	// 输出
	return decryptOutput(plaintext)
}

// ofbDecrypt OFB模式
func ofbDecrypt(block cipher.Block, ciphertext []byte, iv []byte) (string, error) {
	// 加密模式
	blockMode := cipher.NewOFB(block, iv)
	// 创建数组
	plaintext := make([]byte, len(ciphertext))
	// 解密
	blockMode.XORKeyStream(plaintext, ciphertext)
	// 输出
	return decryptOutput(plaintext)
}

// cfbDecrypt CFB模式
func cfbDecrypt(block cipher.Block, ciphertext []byte, iv []byte) (string, error) {
	// 加密模式
	blockMode := cipher.NewCFBDecrypter(block, iv)
	// 创建数组
	plaintext := make([]byte, len(ciphertext))
	// 解密
	blockMode.XORKeyStream(plaintext, ciphertext)
	// 输出
	return decryptOutput(plaintext)
}

// 加密输出
func encryptOutput(way Output, data []byte) (string, error) {
	switch way {
	case Base64Output:
		return base64.StdEncoding.EncodeToString(data), nil
	case HexOutput:
		return hex.EncodeToString(data), nil
	default:
		return "", UnknownOutput
	}
}

// decryptOutput 解密输出
func decryptOutput(data []byte) (string, error) {
	plaintext, err := unPadding(data)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// 解析密文
func parseCiphertext(data string, way Output) ([]byte, error) {
	switch way {
	case Base64Output:
		return base64.StdEncoding.DecodeString(data)
	case HexOutput:
		return hex.DecodeString(data)
	default:
		return nil, UnknownOutput
	}
}
