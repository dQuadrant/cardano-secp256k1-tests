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
import Cardano.Binary (FromCBOR(fromCBOR), ToCBOR(toCBOR), serialize', decodeFull',DecoderError)
import Util.Utils
import Util.Parsers
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Csv as Csv
import Data.Either (isRight)

testClass = "EcdsaSecp256k1Tests"

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
        Left _ -> error "Error: Couldn't deserialise signing key."
        Right sKey -> pure sKey

-- Convert vKeyInHex to appropirate vKey
parseHexVerKey :: String -> IO (VerKeyDSIGN EcdsaSecp256k1DSIGN)
parseHexVerKey vKeyHex = do
    vKeyBytes <- convertToBytes "582102" vKeyHex
    let vKeyE = decodeFull' vKeyBytes
    case vKeyE of 
        Left _ -> error "Error: Couldn't deserialise verification key."
        Right vKey -> pure vKey

tests :: TestTree
tests =
    testGroup "EcdsaSecp256k1 Test" [
        signAndVerifyTest,
        invalidLengthMessageHashTest,
        validLengthMessageHashTest,
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

