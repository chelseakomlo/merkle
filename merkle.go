package merkle

import (
	"crypto/sha256"
	"errors"
)

type merkleTree struct {
	signature []byte
	right     *merkleTree
	left      *merkleTree
}

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

func createMerkleTree(data []string) (*merkleTree, error) {
	m := &merkleTree{}
	if len(data) == 0 {
		return m, errors.New("Must send data of at least one element")
	}
	if len(data) == 1 {
		m.signature = createSha256([]byte(data[0]))
		return m, nil
	}
	mp := len(data) / 2
	m.right, _ = createMerkleTree(data[:mp])
	m.left, _ = createMerkleTree(data[mp:])
	m.signature = createSha256(m.right.signature, m.left.signature)
	return m, nil
}
