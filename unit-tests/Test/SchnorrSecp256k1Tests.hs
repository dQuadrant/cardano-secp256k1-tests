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
import Cardano.Crypto.Hash.SHA3_256 (SHA3_256)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.UTF8 as BSU      -- from utf8-string
import Data.Typeable (typeOf)
import Data.Proxy (Proxy (..))
import Util.Utils
import Util.Parsers
import Cardano.Crypto.Seed(readSeedFromSystemEntropy)
import Data.ByteString.Random (random)
import Cardano.Binary (FromCBOR(fromCBOR), ToCBOR(toCBOR), serialize', decodeFull',DecoderError)

testClass = "SchnorrSecp256k1Tests"

type SchnorrSignatureResult = (VerKeyDSIGN SchnorrSecp256k1DSIGN, String, SigDSIGN SchnorrSecp256k1DSIGN, Bool)

getSignKey :: IO (SignKeyDSIGN SchnorrSecp256k1DSIGN)
getSignKey = do
    seed <- readSeedFromSystemEntropy 32
    pure $ genKeyDSIGN seed

-- Convert sKeyInHex to appropirate sKey
parseHexSignKey :: String -> IO (SignKeyDSIGN SchnorrSecp256k1DSIGN)
parseHexSignKey sKeyHex = do
    sKeyBytes <- convertToBytes "5820" sKeyHex
    let sKeyE = decodeFull' sKeyBytes
    case sKeyE of 
        Left _ -> error "Error: Couldn't deserialise signing key."
        Right sKey -> pure sKey

-- Convert vKeyInHex to appropirate vKey
parseHexVerKey :: String -> IO (VerKeyDSIGN SchnorrSecp256k1DSIGN)
parseHexVerKey vKeyHex = do
    vKeyBytes <- convertToBytes "5820" vKeyHex
    let vKeyE = decodeFull' vKeyBytes
    case vKeyE of 
        Left _ -> error "Error: Couldn't deserialise verification key."
        Right vKey -> pure vKey


-- testsIO :: IO ()
-- testsIO = do
--     sKey <- getSignKey
--     msgBs <- random 64

--     signAndVerify sKey msgBs
--     wrongVerificationKey sKey msgBs
--     wrongMessageRightSignature sKey msgBs
--     rightMessageWrongSignature sKey msgBs

tests :: TestTree
tests =
    testGroup "SchnorrSecp256k1 Test" [
--         signAndVerifyTest,
--         wrongVerificationKeyTest,
--         wrongMessageRightSignatureTest,
--         rightMessageWrongSignatureTest,
    ]

-- signAndVerifyTest :: TestTree
-- signAndVerifyTest = testCase "should sign and verify successfully" signAndVerify

-- wrongVerificationKeyTest :: TestTree
-- wrongVerificationKeyTest = testCase "should return Left error when trying to use wrong verification key." wrongVerificationKey

-- wrongMessageRightSignatureTest :: TestTree
-- wrongMessageRightSignatureTest = testCase "should return Left error when trying to use wrong message and signature." wrongMessageRightSignature

-- rightMessageWrongSignatureTest :: TestTree
-- rightMessageWrongSignatureTest = testCase "should return Left error when trying to use wrong message and signature." rightMessageWrongSignature


signAndVerify :: SignKeyDSIGN SchnorrSecp256k1DSIGN -> String -> SchnorrSignatureResult
signAndVerify sKey msg = do
    let msgBs = BSU.fromString msg
        signature = signDSIGN () msgBs sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey msgBs signature
    case result of 
        Left err -> (vKey, msg, signature, False) 
        Right _ -> (vKey, msg, signature, True)

wrongVerificationKey :: SignKeyDSIGN SchnorrSecp256k1DSIGN -> VerKeyDSIGN SchnorrSecp256k1DSIGN -> String -> SchnorrSignatureResult
wrongVerificationKey sKey wrongVKey msg = do
    let msgBs = BSU.fromString msg
        signature = signDSIGN () msgBs sKey
        result = verifyDSIGN () wrongVKey msgBs signature
    case result of 
        Left err -> (wrongVKey, msg, signature, False) 
        Right _ -> (wrongVKey, msg, signature, True)

wrongMessageRightSignature ::SignKeyDSIGN SchnorrSecp256k1DSIGN -> String -> IO SchnorrSignatureResult
wrongMessageRightSignature sKey msg = do
    msgBs' <- random 64
    let msgBs = BSU.fromString msg
        signature = signDSIGN () msgBs sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey msgBs' signature
    case result of 
        Left err -> pure (vKey, toHex msgBs' 0, signature, False) 
        Right _ -> pure (vKey, toHex msgBs' 0, signature, True)

rightMessageWrongSignature ::SignKeyDSIGN SchnorrSecp256k1DSIGN -> String -> IO SchnorrSignatureResult
rightMessageWrongSignature sKey msg = do
    msgBs' <- random 64
    let msgBs = BSU.fromString msg
        signature1 = signDSIGN () msgBs sKey
        signature2 = signDSIGN () msgBs' sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey msgBs signature2
    case result of 
        Left err -> pure (vKey, msg, signature2, False) 
        Right _ -> pure (vKey, msg, signature2, True)
