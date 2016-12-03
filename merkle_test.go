package merkle

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type MerkelSuite struct{}

var _ = Suite(&MerkelSuite{})

func (s *MerkelSuite) TestBuildEmptyTreeReturnsError(c *C) {
	_, err := merkleTreeHash(make([]string, 0))
	c.Assert(err.Error(), Equals, "Must send data of at least one element")
}

func (s *MerkelSuite) TestBuildTreeOfOneElement(c *C) {
	exp := createSha256([]byte("one"))
	t, _ := merkleTreeHash([]string{"one"})
	c.Assert(exp, DeepEquals, t)
}

func (s *MerkelSuite) TestBuildTreeOfTwoElements(c *C) {
	a, b := createSha256([]byte("one")), createSha256([]byte("two"))
	exp := createSha256(a, b)
	t, _ := merkleTreeHash([]string{"one", "two"})
	c.Assert(exp, DeepEquals, t)
}

func (s *MerkelSuite) TestBuildTreeOfFourElements(c *C) {
	a, b := createSha256([]byte("one")), createSha256([]byte("two"))
	first := createSha256(a, b)
	d, e := createSha256([]byte("three")), createSha256([]byte("four"))
	second := createSha256(d, e)
	exp := createSha256(first, second)
	t, _ := merkleTreeHash([]string{"one", "two", "three", "four"})
	c.Assert(exp, DeepEquals, t)
}
