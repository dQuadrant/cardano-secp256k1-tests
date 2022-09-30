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

import Test.Tasty
import Test.Tasty.HUnit
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

type SchnorrSignatureResult = (VerKeyDSIGN SchnorrSecp256k1DSIGN, SigDSIGN SchnorrSecp256k1DSIGN, Bool)

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

tests :: TestTree
tests =
    testGroup "SchnorrSecp256k1 Test" [
        signAndVerifyTest,
        wrongVerificationKeyTest,
        wrongMessageRightSignatureTest,
        rightMessageWrongSignatureTest
    ]

signAndVerifyTest :: TestTree
signAndVerifyTest = testCase "should return True by signing and verifying successfully" $ do
    sKey <- getSignKey
    msgBs <- random 64
    let (_,_,result) = signAndVerify sKey msgBs
    assertBool "Verification failed." result

wrongVerificationKeyTest :: TestTree
wrongVerificationKeyTest = testCase "should return False when trying to use wrong verification key." $ do
    sKey <- getSignKey
    sKey2 <- getSignKey
    let vKey2 = deriveVerKeyDSIGN sKey2
    msgBs <- random 64
    let (_,_,result) = wrongVerificationKey sKey vKey2 msgBs
    assertBool "Failed when using wrong message it verified successfully. Which should not be the case. " $ not result

wrongMessageRightSignatureTest :: TestTree
wrongMessageRightSignatureTest = testCase "should return False when trying to use wrong message and but right signature." $ do
    sKey <- getSignKey
    msgBs <- random 64
    wrongMsgBs <- random 64
    (_,_,result) <- wrongMessageRightSignature sKey msgBs wrongMsgBs
    assertBool "Failed when using wrong message it verified successfully. Which should not be the case. " $ not result

rightMessageWrongSignatureTest :: TestTree
rightMessageWrongSignatureTest = testCase "should return False when trying to use right message but wrong signature." $ do
    sKey <- getSignKey
    msgBs <- random 64
    (_,_,result) <- rightMessageWrongSignature sKey msgBs
    assertBool "Failed wrong signature verified successfully. Which should not be the case. " $ not result

signAndVerify :: SignKeyDSIGN SchnorrSecp256k1DSIGN -> ByteString -> SchnorrSignatureResult
signAndVerify sKey msgBs = do
    let signature = signDSIGN () msgBs sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey msgBs signature
    case result of 
        Left err -> (vKey, signature, False) 
        Right _ -> (vKey, signature, True)

wrongVerificationKey :: SignKeyDSIGN SchnorrSecp256k1DSIGN -> VerKeyDSIGN SchnorrSecp256k1DSIGN -> ByteString -> SchnorrSignatureResult
wrongVerificationKey sKey wrongVKey msgBs = do
    let signature = signDSIGN () msgBs sKey
        result = verifyDSIGN () wrongVKey msgBs signature
    case result of 
        Left err -> (wrongVKey, signature, False) 
        Right _ -> (wrongVKey, signature, True)

wrongMessageRightSignature ::SignKeyDSIGN SchnorrSecp256k1DSIGN -> ByteString -> ByteString -> IO SchnorrSignatureResult
wrongMessageRightSignature sKey msgBs wrongMsgBS = do
    let signature = signDSIGN () msgBs sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey wrongMsgBS signature
    case result of 
        Left err -> pure (vKey, signature, False) 
        Right _ -> pure (vKey, signature, True)

rightMessageWrongSignature :: SignKeyDSIGN SchnorrSecp256k1DSIGN -> ByteString -> IO SchnorrSignatureResult
rightMessageWrongSignature sKey msgBs = do
    msgBs' <- random 64
    let signature1 = signDSIGN () msgBs sKey
        signature2 = signDSIGN () msgBs' sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey msgBs signature2
    case result of 
        Left err -> pure (vKey, signature2, False) 
        Right _ -> pure (vKey, signature2, True)
