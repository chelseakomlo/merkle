package merkle

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type MerkelSuite struct{}

var _ = Suite(&MerkelSuite{})

func createHash(first, second string) []byte {
	a, b := createSha256([]byte(first)), createSha256([]byte(second))
	return createSha256(a, b)
}

func (s *MerkelSuite) TestBuildEmptyTreeReturnsError(c *C) {
	_, err := Create(make([]string, 0))
	c.Assert(err.Error(), Equals, "Must send data of at least one element")
}

func (s *MerkelSuite) TestBuildWithValidInputReturnsNoError(c *C) {
	_, err := Create([]string{"one"})
	c.Assert(err, IsNil)
}

func (s *MerkelSuite) TestTreeOfOneElement(c *C) {
	exp := createSha256([]byte("one"))

	t, _ := Create([]string{"one"})
	c.Assert(t.getHash(), DeepEquals, exp)
}

func (s *MerkelSuite) TestTreeOfTwoElements(c *C) {
	exp := createHash("one", "two")

	t, _ := Create([]string{"one", "two"})
	c.Assert(t.getHash(), DeepEquals, exp)
}

func (s *MerkelSuite) TestTreeOfFourElements(c *C) {
	firstNode := createHash("one", "two")
	secondNode := createHash("three", "four")
	exp := createSha256(firstNode, secondNode)

	t, _ := Create([]string{"one", "two", "three", "four"})
	c.Assert(exp, DeepEquals, t.getHash())
}

func (s *MerkelSuite) TestTreeOfSixElements(c *C) {
	firstNode := createHash("one", "two")
	secondNode := createHash("three", "four")
	thirdNode := createSha256(firstNode, secondNode)
	fourthNode := createHash("five", "six")
	exp := createSha256(thirdNode, fourthNode)

	t, _ := Create([]string{"one", "two", "three", "four", "five",
		"six"})
	c.Assert(exp, DeepEquals, t.getHash())
}

func (s *MerkelSuite) TestTreeOfOddNumberOfElements(c *C) {
	firstNode := createHash("one", "two")
	exp := createSha256(firstNode, createSha256([]byte("three")))

	t, _ := Create([]string{"one", "two"})
	t.Add("three")
	c.Assert(t.getHash(), DeepEquals, exp)
}

func (s *MerkelSuite) TestAuditTreeWithOneElementWhenElementIsNotInTree(c *C) {
	t, _ := Create([]string{"one", "two"})

	_, err := t.getProofFor("three")
	c.Assert(err.Error(), Equals, "Cannot construct audit path for three")
}

func (s *MerkelSuite) TestGetProofInMerkleTreeOfTwoElements(c *C) {
	t, _ := Create([]string{"one", "two"})

	p, _ := t.getProofFor("two")
	c.Assert(p.auditPath[0].getHash(), DeepEquals, createSha256([]byte("one")))
}

func (s *MerkelSuite) TestGetProofInMerkleTreeOfTwoElementsOppositeSide(c *C) {
	t, _ := Create([]string{"one", "two"})

	p, _ := t.getProofFor("one")
	sibling := p.next()
	expectedRoot := createSha256(createSha256([]byte("one")), sibling)
	c.Assert(sibling, DeepEquals, createSha256([]byte("two")))
	c.Assert(expectedRoot, DeepEquals, t.getHash())
}

// TODO finish this refactor
func verify(p *proof, elem string, isLeftNode bool) []byte {
	if isLeftNode {
		proofNode := createSha256([]byte("three"))
		parentNode := createSha256(proofNode, p.next())
		return createSha256(p.next(), parentNode)
	}
	proofNode := createSha256([]byte(elem))
	parentNode := createSha256(p.next(), proofNode)
	return createSha256(parentNode, p.next())
}

func (s *MerkelSuite) TestGetProofInMerkleTreeOfFourElements(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four"})
	p, _ := t.getProofFor("two")

	rootNode := verify(p, "two", false)
	c.Assert(rootNode, DeepEquals, t.getHash())
}

func (s *MerkelSuite) TestGetProofInMerkleTreeOfFourElementsOppositeSide(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four"})
	p, _ := t.getProofFor("three")

	rootNode := verify(p, "two", true)
	c.Assert(rootNode, DeepEquals, t.getHash())
}

func (s *MerkelSuite) TestGetProofInMerkleTreeOfSixElements(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four", "five",
		"six"})
	p, _ := t.getProofFor("three")

	proofNode := createSha256([]byte("three"))
	parentNode := createSha256(proofNode, p.next())
	grandparentNode := createSha256(p.next(), parentNode)
	rootNode := createSha256(grandparentNode, p.next())

	c.Assert(rootNode, DeepEquals, t.getHash())
}

func (s *MerkelSuite) TestNextForProof(c *C) {
	p := &proof{
		auditPath: []node{
			&leaf{hash: []byte{1}},
			&leaf{hash: []byte{2}},
			&leaf{hash: []byte{3}},
		},
	}

	one := p.next()
	c.Assert(one, DeepEquals, []byte{1})
	c.Assert(len(p.auditPath), Equals, 2)

	two := p.next()
	c.Assert(two, DeepEquals, []byte{2})
	c.Assert(len(p.auditPath), Equals, 1)

	three := p.next()
	c.Assert(three, DeepEquals, []byte{3})
	c.Assert(len(p.auditPath), Equals, 0)
}

func (s *MerkelSuite) TestAddForProof(c *C) {
	p := &proof{
		auditPath: make([]node, 0),
	}
	p.add(&leaf{hash: []byte{1}})
	c.Assert(p.auditPath, DeepEquals, []node{&leaf{hash: []byte{1}}})

	p.add(&leaf{hash: []byte{2}})
	exp := []node{
		&leaf{hash: []byte{1}},
		&leaf{hash: []byte{2}},
	}
	c.Assert(p.auditPath, DeepEquals, exp)
}
