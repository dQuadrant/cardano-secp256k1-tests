## Cardano Secp-256k1 Tests

With the support added to cardano to sign and verify using secp 256k1 curve this repo tries to validate the functionality correctness using simple IO tests. Major tests done here are sign and verify by using ecdsa and schnorr with mismatch signtaures and messages, valid invalid length hashes etc. For more details look into the below folders.

Unit Tests and Test Vectors are present in **/unit-tests** folder.

Benchmark code is present in **/benchmarks** folder.

To run the unit tests type the below command, and verify output.

`
cabal test
`


To run the benchmarks run the below command, and verify output.

`
cabal bench
`



To run the test vectors type the below command, and verify output.

`
cabal run vector-tests
`
