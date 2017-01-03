package merkle

import (
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
