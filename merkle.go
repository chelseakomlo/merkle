package merkle

import (
	"crypto/sha256"
	"errors"
)

type node interface {
	createSignature()
	getSignature() []byte
}

type merkleTree struct {
	signature []byte
	right     node
	left      node
}

func (m *merkleTree) createSignature() {
	m.signature = createSha256(m.right.getSignature(), m.left.getSignature())
}

func (m *merkleTree) getSignature() []byte {
	return m.signature
}

type leaf struct {
	signature []byte
	data      string
}

func (l *leaf) createSignature() {
	l.signature = createSha256([]byte(l.data))
}

func (l *leaf) getSignature() []byte {
	return l.signature
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
		data: data,
	}
	l.createSignature()
	return l
}

func (m *merkleTree) createNode(right, left string) {
	m.right = createLeaf(right)
	m.left = createLeaf(left)
	m.createSignature()
}

func createMerkleTree(data []string) (node, error) {
	if len(data) == 0 {
		return &merkleTree{}, errors.New("Must send data of at least one element")
	}
	if len(data) == 1 {
		return createLeaf(data[0]), nil
	}

	m := &merkleTree{}
	if len(data) == 2 {
		m.createNode(data[0], data[1])
		return m, nil
	}
	mp := len(data) / 2
	m.right, _ = createMerkleTree(data[:mp])
	m.left, _ = createMerkleTree(data[mp:])
	m.createSignature()
	return m, nil
}
