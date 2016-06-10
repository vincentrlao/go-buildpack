package toolbox

import (
	"fmt"
	"io"
	"os"
)

const BufferSize  int = 1024
/*
func main() {
	createFile(path)
	contents := []byte("Hello World")
	writeFile(path, contents)
	readFile(path)
	deleteFile(path)
}
*/
func IsFileExist(path string) bool {
	var _, err = os.Stat(path)
	// create file if not exists
	if os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}

func CreateFile(path string) {
	// detect if file exists
	var _, err = os.Stat(path)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		checkError(err)
		defer file.Close()
	}
}

func WriteFile(path string, content []byte) {

	// open file using READ & WRITE permission
	var file, err = os.OpenFile(path, os.O_RDWR, 0644)
	checkError(err)
	defer file.Close()

	// write some text to file
	_, err = file.Write(content)
	checkError(err)
	// save changes
	err = file.Sync()
	checkError(err)
}

func ReadFile(path string) []byte {
	// re-open file
	var file, err = os.OpenFile(path, os.O_RDWR, 0644)
	checkError(err)
	defer file.Close()

	// read file
	var text = make([]byte, BufferSize)
	for {
		n, err := file.Read(text)
		if err != io.EOF {
			checkError(err)
		}
		if n == 0 {
			break
		}
	}
	fmt.Println(string(text))
	checkError(err)

	return text
}

func DeleteFile(path string) {
	// delete file
	var err = os.Remove(path)
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(0)
	}
}