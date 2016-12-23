package merkle

import "fmt"

type node interface {
	getHash() []byte
	getProofForLeaf(d string, p *Proof) bool
}

// Tree is a Merkle Tree with a signature, and left and right branches.
type Tree struct {
	hash  []byte
	right node
	left  node
}

type leaf struct {
	hash []byte
	data string
}

// Proof contains an audit path proving the inclusion of an element in a
// tree
type Proof struct {
	// AuditPath is an array of nodes necessary for a proof
	AuditPath []node
}

func (p *Proof) next() []byte {
	var i node
	i, p.AuditPath = p.AuditPath[0], p.AuditPath[1:]
	return i.getHash()
}

func (p *Proof) add(e node) {
	p.AuditPath = append(p.AuditPath, e)
}

func (m *Tree) getHash() []byte {
	return m.hash
}

func (l *leaf) getHash() []byte {
	return l.hash
}

func (m *Tree) getProofForLeaf(d string, p *Proof) bool {
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

func (l *leaf) getProofForLeaf(d string, p *Proof) bool {
	return l.data == d
}

// GetProofFor returns a proof with the audit path for a particular element,
// if this element is in the tree. Otherwise, return a non-nil error.
func (m *Tree) GetProofFor(e string) (*Proof, error) {
	p := &Proof{}
	exists := m.getProofForLeaf(e, p)
	if !exists {
		return &Proof{}, fmt.Errorf("Cannot construct audit path for %s", e)
	}
	return p, nil
}

func createLeaf(data string) *leaf {
	return &leaf{
		data: data,
		hash: createSha256([]byte(data)),
	}
}

func split(l []*leaf) ([]*leaf, []*leaf) {
	i := len(l)
	if i%2 == 0 {
		return l[:i-2], l[i-2:]
	}
	return l[:i-1], l[i-1:]
}

func createTree(leaves []*leaf) *Tree {
	if len(leaves) == 1 {
		l := leaves[0]
		return &Tree{
			right: &leaf{},
			left:  l,
			hash:  l.getHash(),
		}
	}

	var left, right node

	if len(leaves) == 2 {
		left, right = leaves[0], leaves[1]
	} else {
		l, r := split(leaves)
		left = createTree(l)
		right = createTree(r)
	}

	return &Tree{
		right: right,
		left:  left,
		hash:  createSha256(left.getHash(), right.getHash()),
	}
}

// Create takes a list of data and returns the corresponding Merkle Tree
func Create(data []string) (*Tree, error) {
	if len(data) == 0 {
		return &Tree{}, fmt.Errorf("Must send data of at least one element")
	}

	var leaves []*leaf
	for _, e := range data {
		leaves = append(leaves, createLeaf(e))
	}

	return createTree(leaves), nil
}

// Add accepts a new element and adds it to itself
func (m *Tree) Add(elem string) {
	b := createSha256([]byte(elem))
	m.hash = createSha256(m.hash, b)
}
