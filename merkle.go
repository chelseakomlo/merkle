package merkle

import "fmt"

type node interface {
	getHash() []byte
	getProofForLeaf(d string, p *Proof) bool
}

// Tree is a merkle tree with corresponding methods
type Tree struct {
	hash  []byte
	right node
	left  node
}

type leaf struct {
	hash []byte
	data string
}

// Proof contains an array of nodes proving the inclusion of an element in a
// tree
type Proof struct {
	auditPath []node
}

func (p *Proof) next() []byte {
	var i node
	i, p.auditPath = p.auditPath[0], p.auditPath[1:]
	return i.getHash()
}

func (p *Proof) add(e node) {
	p.auditPath = append(p.auditPath, e)
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

// GetProofFor returns proof with the audit path for a particular element in
// the tree. Returns a proof if the element is in the tree, or an error if the
// element is not in the tree.
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

func split(d []string) ([]string, []string) {
	i := len(d)
	if i%2 == 0 {
		return d[:i-2], d[i-2:]
	}
	return d[:i-1], d[i-1:]
}

func createTree(data []string) *Tree {
	var left, right node

	if len(data) == 1 {
		left = createLeaf(data[0])
		return &Tree{
			right: &Tree{},
			left:  left,
			hash:  left.getHash(),
		}
	} else if len(data) == 2 {
		left, right = createLeaf(data[0]), createLeaf(data[1])
	} else {
		l, r := split(data)
		left = createTree(l)
		right = createTree(r)
	}

	return &Tree{
		right: right,
		left:  left,
		hash:  createSha256(left.getHash(), right.getHash()),
	}
}

// Create takes a list of data and returns the corresponding tree
func Create(data []string) (*Tree, error) {
	if len(data) == 0 {
		return &Tree{}, fmt.Errorf("Must send data of at least one element")
	}

	if len(data) == 1 {
		return &Tree{hash: createSha256([]byte(data[0]))}, nil
	}

	return createTree(data), nil
}

// Add takes a new element and adds this element to it's tree.
func (m *Tree) Add(elem string) {
	b := createSha256([]byte(elem))
	m.hash = createSha256(m.hash, b)
}
