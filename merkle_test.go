package merkle

import (
	"fmt"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type MerkleSuite struct{}

var _ = Suite(&MerkleSuite{})

func createHash(first, second string) []byte {
	a, b := createSha256([]byte(first)), createSha256([]byte(second))
	return createSha256(a, b)
}

func (s *MerkleSuite) TestBuildEmptyTreeReturnsError(c *C) {
	_, err := Create(make([]string, 0))
	c.Assert(err.Error(), Equals, "Must send data of at least one element")
}

func (s *MerkleSuite) TestBuildWithValidInputReturnsNoError(c *C) {
	_, err := Create([]string{"one"})
	c.Assert(err, IsNil)
}

func (s *MerkleSuite) TestTreeOfOneElement(c *C) {
	exp := createSha256([]byte("one"))

	t, _ := Create([]string{"one"})
	c.Assert(t.getHash(), DeepEquals, exp)
}

func (s *MerkleSuite) TestTreeOfTwoElements(c *C) {
	exp := createHash("one", "two")

	t, _ := Create([]string{"one", "two"})
	c.Assert(t.getHash(), DeepEquals, exp)
}

func (s *MerkleSuite) TestTreeOfFourElements(c *C) {
	firstNode := createHash("one", "two")
	secondNode := createHash("three", "four")
	exp := createSha256(firstNode, secondNode)

	t, _ := Create([]string{"one", "two", "three", "four"})
	c.Assert(exp, DeepEquals, t.getHash())
}

func (s *MerkleSuite) TestTreeOfSixElements(c *C) {
	firstNode := createHash("one", "two")
	secondNode := createHash("three", "four")
	thirdNode := createSha256(firstNode, secondNode)
	fourthNode := createHash("five", "six")
	exp := createSha256(thirdNode, fourthNode)

	t, _ := Create([]string{"one", "two", "three", "four", "five",
		"six"})
	c.Assert(exp, DeepEquals, t.getHash())
}

func (s *MerkleSuite) TestCreateTreeOfOddNumberOfElements(c *C) {
	firstNode := createHash("one", "two")
	exp := createSha256(firstNode, createSha256([]byte("three")))

	t, _ := Create([]string{"one", "two", "three"})
	c.Assert(t.getHash(), DeepEquals, exp)
}

func (s *MerkleSuite) TestAddElementToExistingTree(c *C) {
	firstNode := createHash("one", "two")
	exp := createSha256(firstNode, createSha256([]byte("three")))

	t, _ := Create([]string{"one", "two"})
	t.Add("three")
	c.Assert(t.getHash(), DeepEquals, exp)
}

func (s *MerkleSuite) TestAuditTreeWithOneElementWhenElementIsNotInTree(c *C) {
	t, _ := Create([]string{"one", "two"})

	_, err := t.GetProofFor("three")
	c.Assert(err.Error(), Equals, "Cannot construct audit path for three")
}

func (s *MerkleSuite) TestGetProofInMerkleTreeOfTwoElements(c *C) {
	t, _ := Create([]string{"one", "two"})

	p, _ := t.GetProofFor("two")
	c.Assert(p.AuditPath[0].getHash(), DeepEquals, createSha256([]byte("one")))
}

func (s *MerkleSuite) TestGetProofInMerkleTreeOfTwoElementsOppositeSide(c *C) {
	t, _ := Create([]string{"one", "two"})

	p, _ := t.GetProofFor("one")
	sibling := p.AuditPath[0]
	expectedRoot := createSha256(createSha256([]byte("one")), sibling.getHash())
	c.Assert(sibling.getHash(), DeepEquals, createSha256([]byte("two")))
	c.Assert(expectedRoot, DeepEquals, t.getHash())
}

func (s *MerkleSuite) TestGetProofInMerkleTreeOfFourElements(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four"})
	p, _ := t.GetProofFor("two")

	proofNode := createSha256([]byte("two"))
	parentNode := createSha256(p.AuditPath[0].getHash(), proofNode)
	rootNode := createSha256(parentNode, p.AuditPath[1].getHash())
	c.Assert(rootNode, DeepEquals, t.getHash())
}

func (s *MerkleSuite) TestGetProofInMerkleTreeOfFourElementsOppositeSide(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four"})
	p, _ := t.GetProofFor("three")

	proofNode := createSha256([]byte("three"))
	parentNode := createSha256(proofNode, p.AuditPath[0].getHash())
	rootNode := createSha256(p.AuditPath[1].getHash(), parentNode)
	c.Assert(rootNode, DeepEquals, t.getHash())
}

func (s *MerkleSuite) TestGetProofInMerkleTreeOfSixElements(c *C) {
	t, _ := Create([]string{"one", "two", "three", "four", "five",
		"six"})
	p, _ := t.GetProofFor("three")

	proofNode := createSha256([]byte("three"))
	parentNode := createSha256(proofNode, p.AuditPath[0].getHash())
	grandparentNode := createSha256(p.AuditPath[1].getHash(), parentNode)
	rootNode := createSha256(grandparentNode, p.AuditPath[2].getHash())

	c.Assert(rootNode, DeepEquals, t.getHash())
}

func (s *MerkleSuite) TestGetProofInMerkleTreeOfEightElements(c *C) {
	c.Skip("to finish")
	t, _ := Create([]string{"one", "two", "three", "four", "five",
		"six", "seven", "eight"})
	p, _ := t.GetProofFor("three")
	fmt.Println(len(p.AuditPath))

	proofNode := createSha256([]byte("three"))
	parentNode := createSha256(proofNode, p.AuditPath[0].getHash())
	grandparentNode := createSha256(p.AuditPath[1].getHash(), parentNode)
	rootNode := createSha256(grandparentNode, p.AuditPath[2].getHash())

	c.Assert(rootNode, DeepEquals, t.getHash())
}
