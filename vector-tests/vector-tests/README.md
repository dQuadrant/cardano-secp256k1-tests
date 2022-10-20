It contains test vectors for secp256k1.

Tests including vectors for secp256k1 are defined on `vector-tests` and output vectors on csv format is in `csv-outputs` folder It includes:

**ECDSA**
    - Signing and verification successful
    - Invalid length for required parameters check
    - Signing and verification of pre-image message by hashing it
    - Invalid message hash length check for ecdsa
    - Invalid verification key check
    - Invalid message hash check
    - Invalid signature check

**Schnorr**
    - Signing and verification successful
    - Invalid length for required parameters check
    - Invalid verification key check
    - Invalid message check
    - Invalid signature check

To generate the vectors csv output again run the tests:
`cabal test test-crypto-vectors`
