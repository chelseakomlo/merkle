package merkle

import (
	"crypto/sha256"
	"fmt"
)

type node interface {
	getHash() []byte
	getProofForLeaf(d string, p *proof) bool
}

type merkleTree struct {
	hash  []byte
	right node
	left  node
}

type leaf struct {
	hash []byte
	data string
}

type proof struct {
	auditPath []node // array of nodes proving the inclusion of an element
}

func (p *proof) next() []byte {
	var i node
	i, p.auditPath = p.auditPath[0], p.auditPath[1:]
	return i.getHash()
}

func (p *proof) add(e node) {
	p.auditPath = append(p.auditPath, e)
}

func (m *merkleTree) getHash() []byte {
	return m.hash
}

func (l *leaf) getHash() []byte {
	return l.hash
}

func (m *merkleTree) getProofForLeaf(d string, p *proof) bool {
	if m.right.getProofForLeaf(d, p) {
		p.add(m.left)
		return true
	}
	if m.left.getProofForLeaf(d, p) {
		p.add(m.right)
		return true
	}
	return false
}

func (l *leaf) getProofForLeaf(d string, p *proof) bool {
	return l.data == d
}

func (m *merkleTree) getProofFor(e string) (*proof, error) {
	p := &proof{}
	exists := m.getProofForLeaf(e, p)
	if !exists {
		return &proof{}, fmt.Errorf("Cannot construct audit path for %s", e)
	}
	return p, nil
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
	return &leaf{
		data: data,
		hash: createSha256([]byte(data)),
	}
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
		right: right,
		left:  left,
		hash:  createSha256(right.getHash(), left.getHash()),
	}
}

func createMerkleTree(data []string) (*merkleTree, error) {
	if len(data) == 0 {
		return &merkleTree{}, fmt.Errorf("Must send data of at least one element")
	}

	if len(data) == 1 {
		return &merkleTree{hash: createSha256([]byte(data[0]))}, nil
	}

	return createTree(data), nil
}
