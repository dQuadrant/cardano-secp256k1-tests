{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE TypeApplications #-}

module Test.SchnorrSecp256k1Tests
where

import Cardano.Crypto.DSIGN (
  EcdsaSecp256k1DSIGN,
  SchnorrSecp256k1DSIGN,
  MessageHash,
  toMessageHash,
  DSIGNAlgorithm (..),
  sizeVerKeyDSIGN,
  sizeSignKeyDSIGN,
  sizeSigDSIGN,
  encodeVerKeyDSIGN,
  decodeVerKeyDSIGN,
  encodeSignKeyDSIGN,
  decodeSignKeyDSIGN,
  encodeSigDSIGN,
  decodeSigDSIGN,
  signDSIGN,
  deriveVerKeyDSIGN,
  verifyDSIGN,
  genKeyDSIGN,
  seedSizeDSIGN,
  hashAndPack,
  )

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)
import     Cardano.Crypto.Hash.SHA3_256 (SHA3_256)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.UTF8 as BSU      -- from utf8-string
import Data.Typeable (typeOf)
import Data.Proxy (Proxy (..))

import Cardano.Crypto.Seed(readSeedFromSystemEntropy)

import Data.ByteString.Random (random)

testClass = "SchnorrSecp256k1"

getSignKey :: IO (SignKeyDSIGN SchnorrSecp256k1DSIGN)
getSignKey = do
    seed <- readSeedFromSystemEntropy 32
    pure $ genKeyDSIGN seed

testsIO :: IO ()
testsIO = do
    signAndVerify
    wrongVerificationKey
    wrongMessageSignature

tests :: TestTree
tests =
    testGroup "SchnorrSecp256k1 Test" [
        signAndVerifyTest,
        wrongVerificationKeyTest,
        wrongMessageSignatureTest
    ]

signAndVerifyTest :: TestTree
signAndVerifyTest = testCase "should sign and verify successfully" signAndVerify

wrongVerificationKeyTest :: TestTree
wrongVerificationKeyTest = testCase "should return Left error when trying to use wrong verification key." wrongVerificationKey

wrongMessageSignatureTest :: TestTree
wrongMessageSignatureTest = testCase "should return Left error when trying to use wrong message and signature." wrongMessageSignature

signAndVerify :: IO ()
signAndVerify = do
    sKey <- getSignKey
    msgBs <- random 64
    let signature = signDSIGN () msgBs sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey msgBs signature
    case result of 
        Left err -> error "signAndVerifyTest: Failed: Couldn't verify the signature."
        Right _ -> putStrLn $ "\n"++testClass++": signAndVerifyTest: Working: Signed and verified successfully.\n"

wrongVerificationKey :: IO ()
wrongVerificationKey = do
    sKey <- getSignKey
    sKey2 <- getSignKey
    msgBs <- random 64
    let signature = signDSIGN () msgBs sKey
        vKey = deriveVerKeyDSIGN sKey2
        result = verifyDSIGN () vKey msgBs signature
    case result of 
        Left err -> putStrLn $ "\n" ++testClass ++ ": wrongVerificationKeyTest: Working: Error Couldn't verify the signature which is expected. Actual error: " ++ err
        Right _ -> error $ "\n" ++testClass++": wrongVerificationKeyTest: Failed: Signed and verified successfully which is not expected.\n"

wrongMessageSignature :: IO ()
wrongMessageSignature = do
    sKey <- getSignKey
    msgBs <- random 64
    msgBs' <- random 64
    let signature = signDSIGN () msgBs sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey msgBs' signature
    case result of 
        Left err -> putStrLn $ "\n" ++testClass ++ ": wrongMessageSignatureTest: Working: Error Couldn't verify the signature which is expected. Actual error: " ++ err
        Right _ -> error $ "\n" ++testClass++": wrongMessageSignatureTest: Failed: Signed and verified successfully which is not expected.\n"
