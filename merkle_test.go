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
	firstNode := createSignature("one", "two")
	secondNode := createSignature("three", "four")
	exp := createSha256(firstNode, secondNode)
	t, _ := createMerkleTree([]string{"one", "two", "three", "four"})
	c.Assert(exp, DeepEquals, t.getSignature())
}

func (s *MerkelSuite) TestAuditTreeWithOneElementWhenElementIsNotInTree(c *C) {
	c.Skip("yeah should do this")
}

func (s *MerkelSuite) TestGetProofInMerkleTreeOfTwoElements(c *C) {
	t, _ := createMerkleTree([]string{"one", "two"})
	p := t.getProofFor("two")
	c.Assert(p.data[0], DeepEquals, createSha256([]byte("one")))
}

func (s *MerkelSuite) TestGetProofInMerkleTreeOfTwoElementsOppositeSide(c *C) {
	t, _ := createMerkleTree([]string{"one", "two"})
	p := t.getProofFor("one")
	c.Assert(p.next(), DeepEquals, createSha256([]byte("two")))
}

func (s *MerkelSuite) TestGetProofInMerkleTreeOfFourElements(c *C) {
	t, _ := createMerkleTree([]string{"one", "two", "three", "four"})
	p := t.getProofFor("two")

	proofNode := createSha256([]byte("two"))
	parentNode := createSha256(p.next(), proofNode)
	rootNode := createSha256(parentNode, p.next())

	c.Assert(rootNode, DeepEquals, t.getSignature())
}

func (s *MerkelSuite) TestGetProofInMerkleTreeOfFourElementsOppositeSide(c *C) {
	t, _ := createMerkleTree([]string{"one", "two", "three", "four"})
	p := t.getProofFor("three")

	proofNode := createSha256([]byte("three"))
	parentNode := createSha256(proofNode, p.next())
	rootNode := createSha256(p.next(), parentNode)

	c.Assert(rootNode, DeepEquals, t.getSignature())
}

func (s *MerkelSuite) TestNextForProof(c *C) {
	p := &proof{
		data: [][]byte{[]byte{1}, []byte{2}, []byte{3}},
	}
	one := p.next()
	c.Assert(one, DeepEquals, []byte{1})
	c.Assert(len(p.data), Equals, 2)
	two := p.next()
	c.Assert(two, DeepEquals, []byte{2})
	c.Assert(len(p.data), Equals, 1)
	three := p.next()
	c.Assert(three, DeepEquals, []byte{3})
	c.Assert(len(p.data), Equals, 0)
}

func (s *MerkelSuite) TestAddForProof(c *C) {
	p := &proof{
		data: make([][]byte, 0),
	}
	p.add([]byte{1})
	c.Assert(p.data, DeepEquals, [][]byte{[]byte{1}})
	p.add([]byte{2})
	c.Assert(p.data, DeepEquals, [][]byte{[]byte{1}, []byte{2}})
}
