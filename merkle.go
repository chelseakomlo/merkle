package merkle

import "fmt"

type direction int

// What position the element is in the tree
const (
	RIGHT direction = iota
	LEFT
)

type node interface {
	getHash() []byte
	getProofForLeaf(d string, p *Proof) bool
	getPosition() direction
}

// Tree is a Merkle Tree with a signature, and left and right branches.
type Tree struct {
	hash     []byte
	right    node
	left     node
	position direction
}

type leaf struct {
	hash     []byte
	data     string
	position direction
}

func (m *Tree) getHash() []byte {
	return m.hash
}

func (l *leaf) getHash() []byte {
	return l.hash
}

func (m *Tree) getPosition() direction {
	return m.position
}

func (l *leaf) getPosition() direction {
	return l.position
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
	p := &Proof{elem: e, root: m.getHash()}
	exists := m.getProofForLeaf(e, p)
	if !exists {
		return &Proof{}, fmt.Errorf("Cannot construct audit path for %s", e)
	}
	return p, nil
}

func createLeaf(data string, pos int) *leaf {
	return &leaf{
		data:     data,
		hash:     createSha256([]byte(data)),
		position: direction(pos % 2),
	}
}

func split(l []*leaf) ([]*leaf, []*leaf) {
	i := len(l)
	if i%2 == 0 {
		return l[:i-2], l[i-2:]
	}
	return l[:i-1], l[i-1:]
}

// TODO maybe make a wrapper so the signature with initializing the direction
// isn't exposed everywhere
func createTree(leaves []*leaf, d direction) *Tree {
	if len(leaves) == 1 {
		l := leaves[0]
		return &Tree{
			right:    &leaf{},
			left:     l,
			hash:     l.getHash(),
			position: d,
		}
	}

	var left, right node

	if len(leaves) == 2 {
		left, right = leaves[0], leaves[1]
	} else {
		l, r := split(leaves)
		left = createTree(l, LEFT)
		right = createTree(r, RIGHT)
	}

	return &Tree{
		right:    right,
		left:     left,
		hash:     createSha256(left.getHash(), right.getHash()),
		position: d,
	}
}

// Create takes a list of data and returns the corresponding Merkle Tree
func Create(data []string) (*Tree, error) {
	if len(data) == 0 {
		return &Tree{}, fmt.Errorf("Must send data of at least one element")
	}

	var leaves []*leaf
	for i, e := range data {
		leaves = append(leaves, createLeaf(e, i))
	}

	return createTree(leaves, LEFT), nil
}

// Add accepts a new element and adds it to itself
func (m *Tree) Add(elem string) {
	b := createSha256([]byte(elem))
	m.hash = createSha256(m.hash, b)
}
