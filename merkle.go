package merkle

import (
	"crypto/sha256"
	"errors"
)

type node interface {
	getSignature() []byte
	getLeaf(d string) (bool, *leaf)
}

type merkleTree struct {
	signature []byte
	right     node
	left      node
}

type leaf struct {
	signature []byte
	data      string
}

type proof struct {
	grandparent *merkleTree
	parent      *merkleTree
	sibling     *leaf
}

func (m *merkleTree) getSignature() []byte {
	return m.signature
}

func (l *leaf) getSignature() []byte {
	return l.signature
}

func (m *merkleTree) getLeaf(d string) (bool, *leaf) {
	hasLeaf, l := m.right.getLeaf(d)
	if hasLeaf {
		return true, l
	}
	return m.left.getLeaf(d)
}

func (l *leaf) getLeaf(d string) (bool, *leaf) {
	return (l.data == d), l
}

func (m *merkleTree) getProofFor(e string) (*proof, error) {
	return &proof{}, errors.New("This element is not a member")
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
	var left, right node

	if len(data) == 2 { // does not support uneven trees
		right, left = createLeaf(data[0]), createLeaf(data[1])
	} else {
		mp := len(data) / 2
		right, left = createTree(data[:mp]), createTree(data[mp:])
	}

	return &merkleTree{
		right:     right,
		left:      left,
		signature: createSha256(right.getSignature(), left.getSignature()),
	}
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
