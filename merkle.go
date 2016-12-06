package merkle

import (
	"crypto/sha256"
	"errors"
)

type node interface{}

type merkleTree struct {
	signature []byte
	right     node
	left      node
}

type leaf struct {
	signature []byte
	data      string
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

func createLeaf(data string) *leaf {
	l := &leaf{
		data:      data,
		signature: createSha256([]byte(data)),
	}
	return l
}

func createTree(data []string) *merkleTree {
	var m *merkleTree
	if len(data) == 2 {
		right := createLeaf(data[0])
		left := createLeaf(data[1])
		m = &merkleTree{
			right:     right,
			left:      left,
			signature: createSha256(right.signature, left.signature),
		}
	} else {
		mp := len(data) / 2
		right := createTree(data[:mp])
		left := createTree(data[mp:])
		m = &merkleTree{
			right:     right,
			left:      left,
			signature: createSha256(right.signature, left.signature),
		}
	}
	return m
}

func createMerkleTree(data []string) (*merkleTree, error) {
	if len(data) == 0 {
		return &merkleTree{}, errors.New("Must send data of at least one element")
	}

	if len(data) == 1 {
		return &merkleTree{signature: createSha256([]byte(data[0]))}, nil
	}

	return createTree(data), nil
}
