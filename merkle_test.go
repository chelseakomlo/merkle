package merkle

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type MerkelSuite struct{}

var _ = Suite(&MerkelSuite{})

func createSignature(first, second string) []byte {
	a, b := createSha256([]byte(first)), createSha256([]byte(second))
	return createSha256(a, b)
}

func (s *MerkelSuite) TestBuildEmptyTreeReturnsError(c *C) {
	_, err := createMerkleTree(make([]string, 0))
	c.Assert(err.Error(), Equals, "Must send data of at least one element")
}

func (s *MerkelSuite) TestBuildWithValidInputReturnsNoError(c *C) {
	_, err := createMerkleTree([]string{"one"})
	c.Assert(err, IsNil)
}

func (s *MerkelSuite) TestSignatureOfOneElement(c *C) {
	exp := createSha256([]byte("one"))
	t, _ := createMerkleTree([]string{"one"})
	c.Assert(t.getSignature(), DeepEquals, exp)
}

func (s *MerkelSuite) TestSignatureOfTwoElements(c *C) {
	exp := createSignature("one", "two")
	t, _ := createMerkleTree([]string{"one", "two"})
	c.Assert(t.getSignature(), DeepEquals, exp)
}

func (s *MerkelSuite) TestSignatureOfFourElements(c *C) {
	first := createSignature("one", "two")
	second := createSignature("three", "four")
	exp := createSha256(first, second)
	t, _ := createMerkleTree([]string{"one", "two", "three", "four"})
	c.Assert(exp, DeepEquals, t.getSignature())
}

func (s *MerkelSuite) TestAuditTreeWithOneElementWhenElementIsNotInTree(c *C) {
	t, _ := createMerkleTree([]string{"one"})
	_, err := t.getProofFor("two")
	c.Assert(err.Error(), Equals, "This element is not a member")
}

func (s *MerkelSuite) TestAuditTreeWithOneElementWhenElementIsInTree(c *C) {
}

func (s *MerkelSuite) TestFindLeafInMerkleTreeOfTwoElements(c *C) {
	t, _ := createMerkleTree([]string{"one", "two"})
	exists, l := t.getLeaf("one")
	c.Assert(exists, Equals, true)
	c.Assert(l.data, Equals, "one")
}

func (s *MerkelSuite) TestFindLeafInMerkleTreeOfFourElements(c *C) {
	t, _ := createMerkleTree([]string{"one", "two", "three", "four"})
	exists, l := t.getLeaf("three")
	c.Assert(exists, Equals, true)
	c.Assert(l.data, Equals, "three")
}
