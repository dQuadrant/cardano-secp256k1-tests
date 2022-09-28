Cardano Secp-256k1 Tests

With the support added to cardano to sign and verify using secp 256k1 curve this repo tries to validate the functionality correctness using simple IO tests.

Tests are present in **/tests** folder


To run the tests run the below command, it is used as an executable instead of cabal test to facilitate output printing without extra configuration.

`
cabal run secp256-tests
`
