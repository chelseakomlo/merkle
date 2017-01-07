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
	sibling := p.AuditPath[0]
	expectedRoot := createSha256(createSha256([]byte("one")), sibling.getHash())
	c.Assert(sibling.getHash(), DeepEquals, createSha256([]byte("two")))
	c.Assert(expectedRoot, DeepEquals, t.getHash())
}

func (s *ProofSuite) TestGetProofInMerkleTreeOfFourElements(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four"})
	p, _ := t.GetProofFor("two")

	proofNode := createSha256([]byte("two"))
	parentNode := createSha256(p.AuditPath[0].getHash(), proofNode)
	rootNode := createSha256(parentNode, p.AuditPath[1].getHash())
	c.Assert(rootNode, DeepEquals, t.getHash())
}

func (s *ProofSuite) TestGetProofInMerkleTreeOfFourElementsOppositeSide(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four"})
	p, _ := t.GetProofFor("three")

	proofNode := createSha256([]byte("three"))
	parentNode := createSha256(proofNode, p.AuditPath[0].getHash())
	rootNode := createSha256(p.AuditPath[1].getHash(), parentNode)
	c.Assert(rootNode, DeepEquals, t.getHash())
}

func (s *ProofSuite) TestGetProofInMerkleTreeOfSixElements(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four", "five",
		"six"})
	p, _ := t.GetProofFor("three")

	proofNode := createSha256([]byte("three"))
	parentNode := createSha256(proofNode, p.AuditPath[0].getHash())
	grandparentNode := createSha256(p.AuditPath[1].getHash(), parentNode)
	rootNode := createSha256(grandparentNode, p.AuditPath[2].getHash())

	c.Assert(rootNode, DeepEquals, t.getHash())
}

func (s *ProofSuite) TestValidateProofForMerkleTreeOfTwoElementsOppositeSide(c *C) {
	t, _ := Create([]string{"one", "two"})

	p, _ := t.GetProofFor("one")
	sibling := p.AuditPath[0]
	expectedRoot := createSha256(createSha256([]byte("one")), sibling.getHash())
	c.Assert(sibling.getHash(), DeepEquals, createSha256([]byte("two")))
	c.Assert(expectedRoot, DeepEquals, t.getHash())
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
