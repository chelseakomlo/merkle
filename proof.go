package merkle

// Proof contains an audit path proving the inclusion of an element in a tree
type Proof struct {
	// AuditPath is an array of nodes necessary to reconstruct a proof
	// TODO this doesn't have to be an array, a proof can hold just a sibling,
	// parent, and root node.
	AuditPath []node
	root      []byte
	elem      string
}

func (p *Proof) next() []byte {
	var i node
	// TODO catch failure if the list is at the last element
	i, p.AuditPath = p.AuditPath[0], p.AuditPath[1:]
	return i.getHash()
}

func (p *Proof) add(e node) {
	p.AuditPath = append(p.AuditPath, e)
}

func areBytesEqual(a, b []byte) bool {
	for i, e := range a {
		if e != b[i] {
			return false
		}
	}
	return true
}

// Validate determines whether the audit path can be reconstructed for a single
// element. If it can be (and therefore is an element in the tree), return
// true, otherwise return false.
func (p *Proof) Validate() bool {
	if len(p.AuditPath) == 0 {
		return false
	}
	var first []byte
	proofNode := createSha256([]byte(p.elem))

	if p.AuditPath[0].getPosition() == LEFT {
		first = createSha256(proofNode, p.next())
	} else {
		first = createSha256(p.next(), proofNode)
	}

	if len(p.AuditPath) == 0 {
		return areBytesEqual(p.root, first)
	}

	var next []byte
	if p.AuditPath[0].getPosition() == LEFT {
		next = createSha256(p.next(), first)
	} else {
		next = createSha256(first, p.next())
	}
	return areBytesEqual(p.root, next)
}
