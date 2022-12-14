{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

module Test.SchnorrSecp256k1Tests
  ( tests,
  )
where

import Cardano.Binary (DecoderError (..), decodeFull')
import Cardano.Crypto.DSIGN
  ( DSIGNAlgorithm (..),
    SchnorrSecp256k1DSIGN,
    deriveVerKeyDSIGN,
    genKeyDSIGN,
    signDSIGN,
    verifyDSIGN,
  )
import Cardano.Crypto.Seed (readSeedFromSystemEntropy)
import Codec.CBOR.Read (DeserialiseFailure (..))
import Data.ByteString (ByteString)
import Data.ByteString.Random (random)
import Data.Either (isLeft)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)
import Util.StringConstants (cannotDecodeVerificationKeyError, invalidSchnorrSignatureLengthError, invalidSchnorrVerificationKeyLengthError, unexpectedDecodingError)
import Util.Utils (convertToBytes)

type SchnorrSignatureResult = (VerKeyDSIGN SchnorrSecp256k1DSIGN, SigDSIGN SchnorrSecp256k1DSIGN, Bool)

getSignKey :: IO (SignKeyDSIGN SchnorrSecp256k1DSIGN)
getSignKey = do
  seed <- readSeedFromSystemEntropy 32
  pure $ genKeyDSIGN seed

-- Convert vKeyInHex to appropirate vKey
parseHexVerKey :: String -> IO (Either DecoderError (VerKeyDSIGN SchnorrSecp256k1DSIGN))
parseHexVerKey vKeyHex = do
  vKeyBytes <- convertToBytes vKeyHex
  pure $ decodeFull' vKeyBytes

tests :: TestTree
tests =
  testGroup
    "SchnorrSecp256k1 Unit Tests"
    [ signAndVerifyTest,
      wrongVerificationKeyTest,
      invalidLengthVerificationKeyTest,
      invalidLengthSignatureTest,
      verificationKeyNotOnCurveTest,
      wrongMessageRightSignatureTest,
      rightMessageWrongSignatureTest
    ]

signAndVerifyTest :: TestTree
signAndVerifyTest = testCase "should return True by signing and verifying successfully" $ do
  sKey <- getSignKey
  msgBs <- random 64
  let (_, _, result) = signAndVerify sKey msgBs
  assertBool "Verification failed." result

invalidLengthVerificationKeyTest :: TestTree
invalidLengthVerificationKeyTest = testCase "should return wrong length error when invalid verification key length used." $ do
  let invalidLengthVKey = "02D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22D"
  result <- parseHexVerKey invalidLengthVKey
  assertBool "Failed invalid length verification key is treated as valid." $ isLeft result
  case result of
    Left (DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err)) -> assertEqual "Expected wrong length error returned." (invalidSchnorrVerificationKeyLengthError invalidLengthVKey) err
    Left _ -> error unexpectedDecodingError
    Right _ -> error "Test failed. Sign and verified when using invalid length verification key should not be successful."

invalidLengthSignatureTest :: TestTree
invalidLengthSignatureTest = testCase "should return wrong length error when invalid signature length used." $ do
  let invalidSignature = "8c29c80b168a3b7a6fa90bb17785e25205ff09bc01616115b00f81a17d1eb6dbea1a0c02aa138a7b2af1557fb762d0d9e6d8742adff4013c7d064612ebc27f"
  signatureBytes <- convertToBytes invalidSignature
  let result = decodeFull' signatureBytes :: Either DecoderError (SigDSIGN SchnorrSecp256k1DSIGN)
  assertBool "Failed invalid length verification key is treated as valid." $ isLeft result
  case result of
    Left (DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err)) -> assertEqual "Expected wrong length error returned." (invalidSchnorrSignatureLengthError invalidSignature) err
    Left _ -> error unexpectedDecodingError
    Right _ -> error "Test failed. Sign and verified when using invalid length signature should not be successful."

verificationKeyNotOnCurveTest :: TestTree
verificationKeyNotOnCurveTest = testCase "should return decode length error when verification key not present on curve used." $ do
  let invalidVKey = "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"
  result <- parseHexVerKey invalidVKey
  assertBool "Failed invalid verification key is treated as valid." $ isLeft result
  case result of
    -- Not helpful error message is returned for now could be better if the actual error was reported
    Left (DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err)) -> assertEqual "Expected cannot decode key error." cannotDecodeVerificationKeyError err
    Left _ -> error unexpectedDecodingError
    Right _ -> error "Test failed. Sign and verified when using verification not on the curve should not be successful."

wrongVerificationKeyTest :: TestTree
wrongVerificationKeyTest = testCase "should return False when trying to use wrong verification key." $ do
  sKey <- getSignKey
  sKey2 <- getSignKey
  let vKey2 = deriveVerKeyDSIGN sKey2
  msgBs <- random 64
  let (_, _, result) = wrongVerificationKey sKey vKey2 msgBs
  assertBool "Test Failed when using wrong message it verified successfully. Which should not be the case. " $ not result

wrongMessageRightSignatureTest :: TestTree
wrongMessageRightSignatureTest = testCase "should return False when trying to use wrong message and but right signature." $ do
  sKey <- getSignKey
  msgBs <- random 64
  wrongMsgBs <- random 64
  (_, _, result) <- wrongMessageRightSignature sKey msgBs wrongMsgBs
  assertBool "Failed when using wrong message it verified successfully. Which should not be the case. " $ not result

rightMessageWrongSignatureTest :: TestTree
rightMessageWrongSignatureTest = testCase "should return False when trying to use right message but wrong signature." $ do
  sKey <- getSignKey
  msgBs <- random 64
  (_, _, result) <- rightMessageWrongSignature sKey msgBs
  assertBool "Failed wrong signature verified successfully. Which should not be the case. " $ not result

signAndVerify :: SignKeyDSIGN SchnorrSecp256k1DSIGN -> ByteString -> SchnorrSignatureResult
signAndVerify sKey msgBs = do
  let signature = signDSIGN () msgBs sKey
      vKey = deriveVerKeyDSIGN sKey
      result = verifyDSIGN () vKey msgBs signature
  case result of
    Left _ -> (vKey, signature, False)
    Right _ -> (vKey, signature, True)

wrongVerificationKey :: SignKeyDSIGN SchnorrSecp256k1DSIGN -> VerKeyDSIGN SchnorrSecp256k1DSIGN -> ByteString -> SchnorrSignatureResult
wrongVerificationKey sKey wrongVKey msgBs = do
  let signature = signDSIGN () msgBs sKey
      result = verifyDSIGN () wrongVKey msgBs signature
  case result of
    Left _ -> (wrongVKey, signature, False)
    Right _ -> (wrongVKey, signature, True)

wrongMessageRightSignature :: SignKeyDSIGN SchnorrSecp256k1DSIGN -> ByteString -> ByteString -> IO SchnorrSignatureResult
wrongMessageRightSignature sKey msgBs wrongMsgBS = do
  let signature = signDSIGN () msgBs sKey
      vKey = deriveVerKeyDSIGN sKey
      result = verifyDSIGN () vKey wrongMsgBS signature
  case result of
    Left _ -> pure (vKey, signature, False)
    Right _ -> pure (vKey, signature, True)

rightMessageWrongSignature :: SignKeyDSIGN SchnorrSecp256k1DSIGN -> ByteString -> IO SchnorrSignatureResult
rightMessageWrongSignature sKey msgBs = do
  msgBs' <- random 64
  let signature2 = signDSIGN () msgBs' sKey
      vKey = deriveVerKeyDSIGN sKey
      result = verifyDSIGN () vKey msgBs signature2
  case result of
    Left _ -> pure (vKey, signature2, False)
    Right _ -> pure (vKey, signature2, True)
