package main

import (
	"fmt"
	"os"
	"gemalto.com/toolbox"
	"path/filepath"
	"bytes"
	"strconv"
)

func main() {

	// cred create user_name user_pwd partition_pwd
	// cred delete user_name
	// cred test user_name user_pwd

	if len(os.Args) != 3 && len(os.Args) != 4 && len(os.Args) != 5 {
		fmt.Println("usage: " + os.Args[0] + " create [user name] [user password] [partition password]");
		fmt.Println("usage: " + os.Args[0] + " delete [user name]");
		fmt.Println("usage: " + os.Args[0] + " test [user name] [user password]");
		os.Exit(1);
	}

	salt := []byte("nUuasfB92eShdt0L") // hard-coded salt temporarily for testing

	switch os.Args[1] {
	case "create":
		if len(os.Args) != 5 {
			fmt.Println("usage: " + os.Args[0] + " create [user name] [user password] [partition password]");
			os.Exit(1);
		}

		nullByte := []byte{0x00}

		user_pwd := []byte(os.Args[3])
		partition_pwd := append([]byte(os.Args[4]), nullByte[:]...)
		fmt.Println(partition_pwd)

		cipherText := toolbox.Pbkdf2Encrypt(user_pwd, salt, partition_pwd)

		dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
		fmt.Println(dir)

		filePath := dir + "/" + os.Args[2] + "cipher"
		fmt.Println(filePath)

		toolbox.CreateFile(filePath)

		toolbox.WriteFile(filePath, cipherText)
	case "delete":
		if len(os.Args) != 3 {
			fmt.Println("usage: " + os.Args[0] + " delete [user name]");
			os.Exit(1);
		}

		dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
		fmt.Println(dir)

		filePath := dir + "/" + os.Args[2] + "cipher"
		fmt.Println(filePath)

		toolbox.DeleteFile(filePath)
	case "test":
		if len(os.Args) != 4 {
			fmt.Println("usage: " + os.Args[0] + " test [user name] [user password]");
			os.Exit(1);
		}

		dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
		fmt.Println(dir)

		filePath := dir + "/" + os.Args[2] + "cipher"
		fmt.Println(filePath)

		cipherText := toolbox.ReadFile(filePath)

		user_pwd := []byte(os.Args[3])

		decipherText := toolbox.Pbkdf2Decrypt(user_pwd, salt, cipherText)

		nullPos := bytes.IndexByte(decipherText, 0)
		pwd := string(decipherText[:nullPos])

		fmt.Println(pwd + " " + strconv.Itoa(nullPos))
	default:
		fmt.Println("Sorry, not implemented :D")
	}
}
