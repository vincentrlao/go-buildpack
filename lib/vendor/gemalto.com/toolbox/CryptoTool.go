package toolbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"bytes"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha1"
)

const iter int = 2048
/*
func main() {

	Password := []byte("password")
	Salt := make([]byte, 16)
	n, err := rand.Read(Salt)
	fmt.Println(n, err, Salt)

	plainText := []byte("Hello, World!")

	cipherText := CBCEncrypt(Password, Salt, plainText)

	decipherText := CBCDecrypt(Password, Salt, cipherText)

	fmt.Printf("%s\n", decipherText)
}
*/
func Pbkdf2Decrypt(password []byte, salt []byte, cipherText []byte) []byte {

	AesKey := pbkdf2.Key(password, salt, iter, 16, sha1.New)
	fmt.Printf("AesKey: %x, Key length is %d\n", AesKey, len(AesKey))

	block, err := aes.NewCipher(AesKey)
	if err != nil {
		panic(fmt.Errorf("Cipher initilization error %s", err))
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(cipherText) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(cipherText) % aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(cipherText, cipherText)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	// fmt.Printf("%s\n", cipherText)
	// Output: exampleplaintext
	return cipherText
}

func Pbkdf2Encrypt(password []byte, salt []byte, plainText []byte) []byte {

	AesKey := pbkdf2.Key(password, salt, iter, 16, sha1.New)
	fmt.Printf("AesKey: %x\n", AesKey)
	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	plainText = PKCS5Padding(plainText, aes.BlockSize)

	block, err := aes.NewCipher(AesKey)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize + len(plainText))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plainText)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	//fmt.Printf("%x\n", ciphertext)
	return ciphertext
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext) % blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}