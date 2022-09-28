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

module Test.EcdsaSecp256k1Tests
where

import Cardano.Crypto.DSIGN (
  EcdsaSecp256k1DSIGN,
  SchnorrSecp256k1DSIGN,
  MessageHash,
  toMessageHash,
  fromMessageHash,
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

testClass = "EcdsaSecp256k1"

getSignKey :: IO (SignKeyDSIGN EcdsaSecp256k1DSIGN)
getSignKey = do
    seed <- readSeedFromSystemEntropy 32
    pure $ genKeyDSIGN seed

tests :: TestTree
tests =
    testGroup "EcdsaSecp256k1 Test" [
        signAndVerifyTest,
        invalidLengthMessageHashTest,
        validLengthMessageHashTest,
        wrongVerificationKeyTest,
        wrongMessageSignatureTest
    ]

signAndVerifyTest :: TestTree
signAndVerifyTest = testCase "should sign and verify successfully" signAndVerify

invalidLengthMessageHashTest :: TestTree
invalidLengthMessageHashTest = testCase "should return Nothing when parsing invalid length message hash." invalidLengthMessageHash

validLengthMessageHashTest :: TestTree
validLengthMessageHashTest = testCase "should return correct message hash with valid length." validLengthMessageHash

wrongVerificationKeyTest :: TestTree
wrongVerificationKeyTest = testCase "should return Left error when trying to use wrong verification key." wrongVerificationKey

wrongMessageSignatureTest :: TestTree
wrongMessageSignatureTest = testCase "should return Left error when trying to use wrong message and signature." wrongMessageSignature


signAndVerify :: IO ()
signAndVerify = do
    sKey <- getSignKey
    msgBs <- random 64
    let mh = hashAndPack (Proxy @SHA3_256) msgBs 
        signature = signDSIGN () mh sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey mh signature
    case result of 
        Left err -> error $ testClass ++ ": signAndVerifyTest: Failed: Couldn't verify the signature."
        Right _ -> putStrLn $ "\n"++testClass++": signAndVerifyTest: Working: Signed and verified successfully.\n"

invalidLengthMessageHash:: IO ()
invalidLengthMessageHash = do
    sKey <- getSignKey
    bs64 <- random 64
    let mh = toMessageHash bs64
    case mh of
        Nothing -> putStrLn $ "\n"++testClass++": invalidLengthMessageHashTest: Working: Invalid message hash length used error thrown which is expected.\n"
        Just _ -> error $ testClass ++ ": invalidLengthMessageHashTest: Failed: toMessageHash function is accepting bytestring other than lenght 32."

validLengthMessageHash:: IO ()
validLengthMessageHash = do
    sKey <- getSignKey
    bs32 <- random 32
    let mh = toMessageHash $ bs32
    case mh of
        Nothing -> error $ testClass ++ ": toMessageHash function failed it shouldn't be as correct length is provided."
        Just mh' -> do
            let mhBs = fromMessageHash mh'
            if BS.length mhBs /= 32 then 
                error "Error Parsed message hash is not of length 32."
                else putStrLn $ "\n"++testClass++": validLengthMessageHashTest: Working: length 32 is accepted.\n"

wrongVerificationKey :: IO ()
wrongVerificationKey = do
    sKey <- getSignKey
    sKey2 <- getSignKey
    msgBs <- random 64
    let mh = hashAndPack (Proxy @SHA3_256) msgBs 
        signature = signDSIGN () mh sKey
        vKey = deriveVerKeyDSIGN sKey2
        result = verifyDSIGN () vKey mh signature
    case result of 
        Left err -> putStrLn $ "\n" ++testClass ++ ": wrongVerificationKeyTest: Working: Error Couldn't verify the signature which is expected. Actual error: " ++ err
        Right _ -> error $ "\n" ++testClass++": wrongVerificationKeyTest: Failed: Signed and verified successfully which is not expected.\n"

wrongMessageSignature :: IO ()
wrongMessageSignature = do
    sKey <- getSignKey
    msgBs <- random 64
    msgBs' <- random 64
    let mh = hashAndPack (Proxy @SHA3_256) msgBs 
    let mh2 = hashAndPack (Proxy @SHA3_256) msgBs'
        signature = signDSIGN () mh sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey mh2 signature
    case result of 
        Left err -> putStrLn $ "\n" ++testClass ++ ": wrongMessageSignatureTest: Working: Error Couldn't verify the signature which is expected. Actual error: " ++ err
        Right _ -> error $ "\n" ++testClass++": wrongMessageSignatureTest: Failed: Signed and verified successfully which is not expected.\n"

testsIO :: IO ()
testsIO = do
    signAndVerify
    invalidLengthMessageHash
    validLengthMessageHash
    wrongVerificationKey
    wrongMessageSignature
