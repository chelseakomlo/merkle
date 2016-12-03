package merkle

import (
	"crypto/sha256"
	"errors"
)

func getIndex(s []string, e string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == e {
			return i
		}
	}
	return -1
}

func flattenOneLevel(b [][]byte) []byte {
	var ret []byte
	for _, i := range b {
		ret = append(ret, i...)
	}
	return ret
}

func createSha256(data ...[]byte) []byte {
	h := sha256.New()
	h.Write(flattenOneLevel(data))
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
	b := createSha256(first, second)
	return b, nil
}
