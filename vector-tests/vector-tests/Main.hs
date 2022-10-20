module Main (main) where

import qualified Test.EcdsaSecp256k1Tests as EcdsaSecp256k1Tests
import qualified Test.SchnorrSecp256k1Tests as SchnorrSecp256k1Tests
import Test.Tasty (TestTree, defaultMain, testGroup)
import qualified TestVector.EcdsaSecp256k1Vectors as EcdsaSecp256k1Vectors
import qualified TestVector.SchnorrSecp256k1Vectors as SchnorrSecp256k1Vectors

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup
    "Secp-256k1 tests"
    [ EcdsaSecp256k1Tests.tests,
      SchnorrSecp256k1Tests.tests,
      EcdsaSecp256k1Vectors.tests,
      SchnorrSecp256k1Vectors.tests
    ]