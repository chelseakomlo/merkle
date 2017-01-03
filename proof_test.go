package merkle

import (
	"testing"

	. "gopkg.in/check.v1"
)

func MerkleTest(t *testing.T) { TestingT(t) }

type ProofSuite struct{}

var _ = Suite(&ProofSuite{})

func (s *ProofSuite) TestAuditTreeWithOneElementWhenElementIsNotInTree(c *C) {
	t, _ := Create([]string{"one", "two"})

	_, err := t.GetProofFor("three")
	c.Assert(err.Error(), Equals, "Cannot construct audit path for three")
}

func (s *ProofSuite) TestGetProofInMerkleTreeOfTwoElements(c *C) {
	t, _ := Create([]string{"one", "two"})

	p, _ := t.GetProofFor("two")
	c.Assert(p.AuditPath[0].getHash(), DeepEquals, createSha256([]byte("one")))
}

func (s *ProofSuite) TestGetProofInMerkleTreeOfTwoElementsOppositeSide(c *C) {
	t, _ := Create([]string{"one", "two"})

	p, _ := t.GetProofFor("one")
	sibling := p.next()
	expectedRoot := createSha256(createSha256([]byte("one")), sibling)
	c.Assert(sibling, DeepEquals, createSha256([]byte("two")))
	c.Assert(expectedRoot, DeepEquals, t.getHash())
}

// TODO finish this refactor
func verify(p *Proof, elem string, isLeftNode bool) []byte {
	if isLeftNode {
		proofNode := createSha256([]byte("three"))
		parentNode := createSha256(proofNode, p.next())
		return createSha256(p.next(), parentNode)
	}
	proofNode := createSha256([]byte(elem))
	parentNode := createSha256(p.next(), proofNode)
	return createSha256(parentNode, p.next())
}

func (s *ProofSuite) TestGetProofInMerkleTreeOfFourElements(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four"})
	p, _ := t.GetProofFor("two")

	rootNode := verify(p, "two", false)
	c.Assert(rootNode, DeepEquals, t.getHash())
}

func (s *ProofSuite) TestGetProofInMerkleTreeOfFourElementsOppositeSide(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four"})
	p, _ := t.GetProofFor("three")

	rootNode := verify(p, "two", true)
	c.Assert(rootNode, DeepEquals, t.getHash())
}

func (s *ProofSuite) TestGetProofInMerkleTreeOfSixElements(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four", "five",
		"six"})
	p, _ := t.GetProofFor("three")

	proofNode := createSha256([]byte("three"))
	parentNode := createSha256(proofNode, p.next())
	grandparentNode := createSha256(p.next(), parentNode)
	rootNode := createSha256(grandparentNode, p.next())

	c.Assert(rootNode, DeepEquals, t.getHash())
}

func (s *ProofSuite) TestValidateProofForMerkleTreeOfTwoElementsOppositeSide(c *C) {
	t, _ := Create([]string{"one", "two"})

	p, _ := t.GetProofFor("one")
	sibling := p.next()
	expectedRoot := createSha256(createSha256([]byte("one")), sibling)
	c.Assert(sibling, DeepEquals, createSha256([]byte("two")))
	c.Assert(expectedRoot, DeepEquals, t.getHash())
}

func (s *ProofSuite) TestNextForProof(c *C) {
	p := &Proof{
		AuditPath: []node{
			&leaf{hash: []byte{1}},
			&leaf{hash: []byte{2}},
			&leaf{hash: []byte{3}},
		},
	}

	one := p.next()
	c.Assert(one, DeepEquals, []byte{1})
	c.Assert(len(p.AuditPath), Equals, 2)

	two := p.next()
	c.Assert(two, DeepEquals, []byte{2})
	c.Assert(len(p.AuditPath), Equals, 1)

	three := p.next()
	c.Assert(three, DeepEquals, []byte{3})
	c.Assert(len(p.AuditPath), Equals, 0)
}

func (s *ProofSuite) TestAddForProof(c *C) {
	p := &Proof{
		AuditPath: make([]node, 0),
	}
	p.add(&leaf{hash: []byte{1}})
	c.Assert(p.AuditPath, DeepEquals, []node{&leaf{hash: []byte{1}}})

	p.add(&leaf{hash: []byte{2}})
	exp := []node{
		&leaf{hash: []byte{1}},
		&leaf{hash: []byte{2}},
	}
	c.Assert(p.AuditPath, DeepEquals, exp)
}

func (s *ProofSuite) TestValidateOnProofLeftSide(c *C) {
	t, _ := Create([]string{"one", "two"})

	p, _ := t.GetProofFor("one")
	c.Assert(p.Validate(), Equals, true)
}

func (s *ProofSuite) TestValidateOnProofRightSide(c *C) {
	t, _ := Create([]string{"one", "two"})

	p, _ := t.GetProofFor("two")
	c.Assert(p.Validate(), Equals, true)
}

func (s *ProofSuite) TestValidateOnProofMultipleNodesLeftSide(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four"})

	p, _ := t.GetProofFor("one")
	c.Assert(p.Validate(), Equals, true)
}

func (s *ProofSuite) TestValidateOnProofMultipleNodesRightSide(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four"})

	p, _ := t.GetProofFor("two")
	c.Assert(p.Validate(), Equals, true)
}

func (s *ProofSuite) TestValidateOnProofMultipleNodesRightBranchLeftSide(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four"})

	p, _ := t.GetProofFor("three")
	c.Assert(p.Validate(), Equals, true)
}

func (s *ProofSuite) TestValidateOnProofMultipleNodesRightBranchRightSide(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four"})

	p, _ := t.GetProofFor("four")
	c.Assert(p.Validate(), Equals, true)
}

func (s *ProofSuite) TestValidateOnProofThreeBranches(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four", "five", "six"})

	p, _ := t.GetProofFor("five")
	c.Assert(p.Validate(), Equals, true)
}

func (s *ProofSuite) TestValidateOnProofWithoutValidElement(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four", "five", "six"})

	p, _ := t.GetProofFor("zero")
	c.Assert(p.Validate(), Equals, false)
}
