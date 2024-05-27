package tools

import "fmt"

func HandleIt(err error) {
	if err != nil {
		fmt.Println(err)
	}
}
