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
  VerKeyDSIGN,
  SigDSIGN
  )
import Test.Tasty
import Test.Tasty.HUnit
import     Cardano.Crypto.Hash.SHA3_256 (SHA3_256)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.UTF8 as BSU      -- from utf8-string
import Data.Typeable (typeOf)
import Data.Proxy (Proxy (..))
import Cardano.Crypto.Seed(readSeedFromSystemEntropy)
import Data.ByteString.Random (random)
import Cardano.Binary (FromCBOR(fromCBOR), ToCBOR(toCBOR), serialize', decodeFull',DecoderError(..))
import Util.Utils
import Util.Parsers
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Csv as Csv
import Data.Either (isRight,isLeft)
import Control.Monad(void)
import Data.Typeable (typeOf)
import Codec.CBOR.Read (DeserialiseFailure(..))
import Data.List (isInfixOf)
import Control.Exception(throw,SomeException(..),try)

type EcdsaSignatureResult = (VerKeyDSIGN EcdsaSecp256k1DSIGN, MessageHash, SigDSIGN EcdsaSecp256k1DSIGN, Bool)

getSignKey :: IO (SignKeyDSIGN EcdsaSecp256k1DSIGN)
getSignKey = do
    seed <- readSeedFromSystemEntropy 32
    pure $ genKeyDSIGN seed

-- Convert sKeyInHex to appropirate sKey
parseHexSignKey :: String -> IO (SignKeyDSIGN EcdsaSecp256k1DSIGN)
parseHexSignKey sKeyHex = do
    sKeyBytes <- convertToBytes "5820" sKeyHex
    let sKeyE = decodeFull' sKeyBytes
    case sKeyE of 
        Left err -> throw err
        Right sKey -> pure sKey

-- Convert vKeyInHex to appropirate vKey
parseHexVerKey :: String -> IO (Either DecoderError (VerKeyDSIGN EcdsaSecp256k1DSIGN))
parseHexVerKey vKeyHex = do
    vKeyBytes <- convertToBytes "582102" vKeyHex
    pure $ decodeFull' vKeyBytes

tests :: TestTree
tests =
    testGroup "EcdsaSecp256k1 Test" [
        signAndVerifyTest,
        invalidLengthMessageHashTest,
        validLengthMessageHashTest,
        invalidLengthVerificationKeyTest,
        invalidLengthSignatureTest,
        verificationKeyNotOnCurveTest,
        wrongVerificationKeyTest,
        wrongMessageRightSignatureTest,
        rightMessageWrongSignatureTest
    ]

signAndVerifyTest :: TestTree
signAndVerifyTest = testCase "should return True by signing and verifying successfully" $ do
    sKey <- getSignKey
    msgBs <- random 64
    let (_,_,_,result) = signAndVerify sKey msgBs
    assertBool "Verification failed." result

invalidLengthMessageHashTest :: TestTree
invalidLengthMessageHashTest = testCase "should return False when parsing invalid length message hash." $ do
    invalidMsgHash <- random 31
    let result = messageHashLengthValidityCheck invalidMsgHash
    assertBool "Failed invalid message hash length is 31." $ not result

validLengthMessageHashTest :: TestTree
validLengthMessageHashTest = testCase "should return True when message hash with valid length used." $ do
    validMsgHash <- random 32
    let result = messageHashLengthValidityCheck validMsgHash
    assertBool "Failed valid message hash length is treated as invalid." result

invalidLengthVerificationKeyTest :: TestTree
invalidLengthVerificationKeyTest = testCase "should return wrong length error when invalid verification key length used." $ do
    let invalidLengthVKey = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA6"
    result <- parseHexVerKey invalidLengthVKey
    assertBool "Failed invalid length verification key is treated as valid." $ isLeft result
    case result of
        -- TODO Not helpful error message is returned for now need to raise the readability
        Left (DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err)) -> assertBool "Expected wrong length error returned." $ isInfixOf "end of input"  err
        Right _ -> error "Error result is right which should not be the case."

invalidLengthSignatureTest :: TestTree
invalidLengthSignatureTest = testCase "should return wrong length error when invalid signature length used." $ do
    let invalidSignature = "c0730606584a92b4a979fdbfbb89a6b304827ab5084e55f61f6c1fbf36cf359b49a8e128aee4bba7fa5b8b0491ba2425aa97a2af668cb4c54fb68dfae8a6756565"
    signatureBytes <- convertToBytes "5820" invalidSignature
    let result = decodeFull' signatureBytes :: Either DecoderError (SigDSIGN EcdsaSecp256k1DSIGN)
    assertBool "Failed invalid length verification key is treated as valid." $ isLeft result
    case result of
        -- TODO Not helpful error message is returned for now need to raise the readability
        Left (DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err)) -> assertBool "Expected wrong length error returned." $ isInfixOf "decodeSigDSIGN: wrong length, expected 64 bytes but got "  err
        Right _ -> error "Error result is right which should not be the case."

verificationKeyNotOnCurveTest :: TestTree
verificationKeyNotOnCurveTest = testCase "should return decode length error when verification key not present on curve used." $ do
    let invalidVKey = "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"
    result <- parseHexVerKey invalidVKey
    assertBool "Failed invalid verification key is treated as valid." $ isLeft result
    case result of
        -- TODO Not helpful error message is returned for now
        Left (DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err)) -> assertBool "Expected cannot decode key error." $ isInfixOf "cannot decode key"  err
        Right _ -> error "Error result is right which should not be the case."

wrongVerificationKeyTest :: TestTree
wrongVerificationKeyTest = testCase "should return False when trying to use wrong verification key." $ do
    sKey <- getSignKey
    sKey2 <- getSignKey
    let vKey2 = deriveVerKeyDSIGN sKey2
    msgBs <- random 64
    let (_,_,_,result) = wrongVerificationKey sKey vKey2 msgBs
    assertBool "Failed when using wrong message it verified successfully. Which should not be the case. " $ not result

wrongMessageRightSignatureTest :: TestTree
wrongMessageRightSignatureTest = testCase "should return False when trying to use wrong message and but right signature." $ do
    sKey <- getSignKey
    msgBs <- random 64
    (_,_,_,result) <- wrongMessageRightSignature sKey msgBs
    assertBool "Failed when using wrong message it verified successfully. Which should not be the case. " $ not result

rightMessageWrongSignatureTest :: TestTree
rightMessageWrongSignatureTest = testCase "should return False when trying to use right message but wrong signature." $ do
    sKey <- getSignKey
    msgBs <- random 64
    (_,_,_,result) <- rightMessageWrongSignature sKey msgBs
    assertBool "Failed wrong signature verified successfully. Which should not be the case. " $ not result

signAndVerify :: SignKeyDSIGN EcdsaSecp256k1DSIGN -> ByteString -> EcdsaSignatureResult
signAndVerify sKey msgBs = do
    let mh = hashAndPack (Proxy @SHA3_256) msgBs 
        signature = signDSIGN () mh sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey mh signature
    case result of 
        Left err -> (vKey, mh, signature, False)
        Right _ -> (vKey, mh, signature, True)

messageHashLengthValidityCheck:: ByteString -> Bool
messageHashLengthValidityCheck validMsgHash = do
    let mh = toMessageHash $ validMsgHash
    case mh of
        Nothing -> False
        Just mh' -> do
            let mhBs = fromMessageHash mh'
            if BS.length mhBs == 32 then True else False

wrongVerificationKey :: SignKeyDSIGN EcdsaSecp256k1DSIGN -> VerKeyDSIGN EcdsaSecp256k1DSIGN -> ByteString -> EcdsaSignatureResult
wrongVerificationKey sKey wrongVKey msgBs = do
    let mh = hashAndPack (Proxy @SHA3_256) msgBs 
        signature = signDSIGN () mh sKey
        result = verifyDSIGN () wrongVKey mh signature
    case result of 
        Left err -> (wrongVKey, mh, signature, False) 
        Right _ -> (wrongVKey, mh, signature, True)

wrongMessageRightSignature :: SignKeyDSIGN EcdsaSecp256k1DSIGN -> ByteString -> IO EcdsaSignatureResult
wrongMessageRightSignature sKey msgBs = do
    msgBs' <- random 64
    let mh = hashAndPack (Proxy @SHA3_256) msgBs 
    let mh2 = hashAndPack (Proxy @SHA3_256) msgBs'
        signature = signDSIGN () mh sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey mh2 signature
    case result of 
        Left err -> pure (vKey,mh2,signature,False)
        Right _ -> pure (vKey,mh2,signature,True)

rightMessageWrongSignature :: SignKeyDSIGN EcdsaSecp256k1DSIGN -> ByteString -> IO EcdsaSignatureResult
rightMessageWrongSignature sKey msgBs = do
    msgBs' <- random 64
    let mh = hashAndPack (Proxy @SHA3_256) msgBs 
    let mh2 = hashAndPack (Proxy @SHA3_256) msgBs'
        signature1 = signDSIGN () mh sKey
        signature2 = signDSIGN () mh2 sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey mh signature2
    case result of 
        Left err -> pure (vKey,mh,signature2,False)
        Right _ -> pure (vKey,mh,signature2,True)

