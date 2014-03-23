package ucenter

import (
	"fmt"
	// "strings"
	"testing"
)

func TestAesEncrypt(t *testing.T) {
	key := "abcyyyiiTT7&*,6T"
	// str := "abc"
	res, err := AesEncrypt("def", []byte(key))

	if err != nil {
		t.Error(err.Error())
		return
	}

	fmt.Println(res)

	dec, err := AesDecrypt(res, []byte(key))
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Println(string(dec))

}
