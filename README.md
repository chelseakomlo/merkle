## Merkle Tree Work in Progress

Not ready for use!

### How to use

This Merkle Tree accepts only leaves of type string, looking something like
this:

`data := []string{"one", "two", "three"}`

You can create a new Merkle Tree like this:

`tree := Create(data)`

Adding an element to an existing tree works like this:

`tree.Add(elem)`

Getting a proof for a specific element in the tree is as follows:

`proof := tree.GetProofFor(elem)`

Verifying a proof is as follows, returning either true or false:

`isValid := proof.Verify()`

### Running tests
`make test`

### Todo
1. Test against other vectors
2. Benchmark
3. Allow ability to specify other hashing algorithms

