Cardano Secp-256k1 Tests

With the support added to cardano to sign and verify using secp 256k1 curve this repo tries to validate the functionality correctness using simple IO tests.

Unit Tests and Test Vectors are present in **/unit-tests** folder

To run the unit tests run the below command, and see output.

`
cabal test
`

To run the test vectors run the below command, and see output.

`
cabal run vector-tests
`
