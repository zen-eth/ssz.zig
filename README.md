[![Lint and test](https://github.com/zen-eth/ssz.zig/actions/workflows/ci.yml/badge.svg)](https://github.com/zen-eth/ssz.zig/actions/workflows/ci.yml)

# ssz.zig
A [Zig](https://ziglang.org) implementation of the [SSZ serialization protocol](https://github.com/ethereum/eth2.0-specs/blob/dev/ssz/simple-serialize.md).

 Tested with zig 0.13.0.

## Serialization

Use `serialize` to write a serialized object to a byte buffer.

Currently supported types:

 * `BitVector[N]`
 * `uintN`
 * `boolean`
 * structures
 * optionals
 * `null`
 * `Vector[N]`
 * **tagged** unions

Ziglang has the limitation that it's not possible to determine which union field is active without tags.

## Deserialization

Use `deserialize` to turn a byte array containing a serialized payload, into an object.

`deserialize` does not allocate any new memory. Scalar values will be copied, and vector values use references to the serialized data. Make a copy of the data if you need to free the serialized payload. Future versions will include a version of `deserialize` that expects an allocator.

Supported types:

 * `uintN`
 * `boolean`
 * structures
 * strings
 * `BitVector[N]`
 * `Vector[N]`
 * unions
 * optionals

## Merkelization (experimental)

Use `tree_root_hash` to calculate the root hash of an object.

Supported types:

 * `Bitvector[N]`
 * `boolean`
 * `uintN`
 * `Vector[N]`
 * structures
 * strings
 * optionals
 * unions

## Contributing

Simply create an issue or a PR.
