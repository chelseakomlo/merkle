package merkle

import (
	"testing"

	. "gopkg.in/check.v1"
)

func UtilsTest(t *testing.T) { TestingT(t) }

type UtilsSuite struct{}

var _ = Suite(&UtilsSuite{})

func (s *UtilsSuite) TestgetIndexOfEmptyList(c *C) {
	var empty []string
	i := getIndex(empty, "one")
	c.Assert(i, Equals, -1)
}

func (s *UtilsSuite) TestgetIndexOfListWhereElementDoesNotExist(c *C) {
	e := []string{"one", "two", "three"}
	i := getIndex(e, "four")
	c.Assert(i, Equals, -1)
}

func (s *UtilsSuite) TestgetIndexOfListWhereElementDoesExist(c *C) {
	e := []string{"one", "two", "three"}
	i := getIndex(e, "one")
	c.Assert(i, Equals, 0)
}

func (s *UtilsSuite) TestgetIndexOfListWhereElementDoesExistDifferentPos(c *C) {
	e := []string{"one", "two", "three"}
	i := getIndex(e, "two")
	c.Assert(i, Equals, 1)
}

func (s *UtilsSuite) TestflattenOneLevel(c *C) {
	e := []byte{1}
	f := []byte{2}
	g := [][]byte{e, f}
	h := flattenOneLevel(g)
	c.Assert(h, DeepEquals, []byte{1, 2})
}
