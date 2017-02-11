package merkle

// Proof contains an audit path proving the inclusion of an element in a tree
type Proof struct {
	// AuditPath is an array of nodes necessary to reconstruct a proof
	AuditPath []node
	root      []byte
	elem      string
}

func (p *Proof) add(e node) {
	p.AuditPath = append(p.AuditPath, e)
}

// Validate determines whether the audit path can be reconstructed for a single
// element. If it can be (and therefore is an element in the tree), return
// true, otherwise return false.
func (p *Proof) Validate() bool {
	if len(p.AuditPath) == 0 {
		return false
	}
	var first []byte
	sibling := p.AuditPath[0]
	proofNode := createSha256([]byte(p.elem))

	if sibling.getPosition() == LEFT {
		first = createSha256(proofNode, sibling.getHash())
	} else {
		first = createSha256(sibling.getHash(), proofNode)
	}

	if len(p.AuditPath) == 1 {
		return areBytesEqual(p.root, first)
	}

	var next []byte
	parent := p.AuditPath[1]

	if parent.getPosition() == LEFT {
		next = createSha256(parent.getHash(), first)
	} else {
		next = createSha256(first, parent.getHash())
	}
	return areBytesEqual(p.root, next)
}
