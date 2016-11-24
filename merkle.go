package merkle

import (
	"crypto/sha256"
	"errors"
)

var dataList = []string{"one", "two", "three", "four"}

func getIndex(s []string, e string) int {
	i := 0
	for i < len(dataList) {
		if s[i] == e {
			return i
		}
		i++
	}
	return -1
}

func createSha256(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}

func merkleTreeHash(data []string) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("Must send data of at least one element")
	}
	if len(data) == 1 {
		return createSha256([]byte(data[0])), nil
	}
	mp := len(data) / 2
	first, _ := merkleTreeHash(data[:mp])
	second, _ := merkleTreeHash(data[mp:])
	b := append(first, second...)
	return createSha256(b), nil
}
