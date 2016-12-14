## Merkle Tree Work in Progress

### How to

Create a new tree:
`tree := Create(data)`

Add an element to an existing tree:
`tree.Add(elem)`

Get a proof for a specific element in the tree:
`proof := tree.GetProofFor(elem)`

### Running tests
`make test`

### Todo
1. Test against other vectors
2. Accept different data types
3. Add licence
4. Add example usage
5. Benchmark

