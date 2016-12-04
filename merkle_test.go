package merkle

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type MerkelSuite struct{}

var _ = Suite(&MerkelSuite{})

func createNode(first, second string) []byte {
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
	exp := createNode("one", "two")
	t, _ := createMerkleTree([]string{"one", "two"})
	c.Assert(t.getSignature(), DeepEquals, exp)
}

func (s *MerkelSuite) TestSingatureOfFourElements(c *C) {
	first := createNode("one", "two")
	second := createNode("three", "four")
	exp := createSha256(first, second)
	t, _ := createMerkleTree([]string{"one", "two", "three", "four"})
	c.Assert(exp, DeepEquals, t.getSignature())
}
