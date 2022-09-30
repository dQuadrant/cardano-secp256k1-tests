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
import Cardano.Binary (FromCBOR(fromCBOR), ToCBOR(toCBOR), serialize', decodeFull',DecoderError)
import Util.Utils
import Util.Parsers
import qualified Data.ByteString.Lazy as BSL

import qualified Data.Csv as Csv

import Data.Either (isRight)

testClass = "EcdsaSecp256k1Tests"

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

-- tests :: TestTree
-- tests =
--     testGroup "EcdsaSecp256k1 Test" [
--         signAndVerifyTest,
--         invalidLengthMessageHashTest,
--         validLengthMessageHashTest,
--         wrongVerificationKeyTest,
--         wrongMessageRightSignatureTest,
--         wrongSignatureRightMessageTest
--     ]

-- testsIO :: IO ()
-- testsIO = do
--     sKey <- getSignKey
--     msgBs <- random 64
--     validMsgHash <- random 32
--     invalidMsgHash <- random 30
    
--     if isRight $ signAndVerify sKey msgBs
--     invalidLengthMessageHash sKey invalidMsgHash
--     validLengthMessageHash sKey validMsgHash
--     wrongVerificationKey sKey msgBs
--     wrongMessageRightSignature sKey msgBs
--     wrongSignatureRightMessage sKey msgBs


--TODO write test matching left right
-- signAndVerifyTest :: TestTree
-- signAndVerifyTest = testCase "should sign and verify successfully" $ isRight $ signAndVerify

-- invalidLengthMessageHashTest :: TestTree
-- invalidLengthMessageHashTest = testCase "should return Nothing when parsing invalid length message hash." invalidLengthMessageHash

-- validLengthMessageHashTest :: TestTree
-- validLengthMessageHashTest = testCase "should return correct message hash with valid length." validLengthMessageHash

-- wrongVerificationKeyTest :: TestTree
-- wrongVerificationKeyTest = testCase "should return Left error when trying to use wrong verification key." wrongVerificationKey

-- wrongMessageRightSignatureTest :: TestTree
-- wrongMessageRightSignatureTest = testCase "should return Left error when trying to use wrong message and signature." wrongMessageRightSignature

-- wrongSignatureRightMessageTest :: TestTree
-- wrongSignatureRightMessageTest = testCase "should return Left error when trying to use wrong message and signature." wrongSignatureRightMessage


signAndVerify :: SignKeyDSIGN EcdsaSecp256k1DSIGN -> ByteString -> SignatureResult
signAndVerify sKey msgBs = do
    let mh = hashAndPack (Proxy @SHA3_256) msgBs 
        signature = signDSIGN () mh sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey mh signature
    case result of 
        Left err -> (vKey, mh, signature, False) 
        Right _ -> (vKey, mh, signature, True)

invalidLengthMessageHashCheck:: ByteString -> Bool
invalidLengthMessageHashCheck invalidMsgHash = do
    let mh = toMessageHash invalidMsgHash
    case mh of
        Nothing -> False
        Just _ -> True

validLengthMessageHash:: SignKeyDSIGN EcdsaSecp256k1DSIGN -> ByteString -> IO ()
validLengthMessageHash sKey validMsgHash = do
    let mh = toMessageHash $ validMsgHash
    case mh of
        Nothing -> error $ testClass ++ ": toMessageHash function failed it shouldn't be as correct length is provided."
        Just mh' -> do
            let mhBs = fromMessageHash mh'
            if BS.length mhBs /= 32 then 
                error "Error Parsed message hash is not of length 32."
                else putStrLn $ "\n"++testClass++": validLengthMessageHashTest: Working: length 32 is accepted.\n"

wrongVerificationKey :: SignKeyDSIGN EcdsaSecp256k1DSIGN -> VerKeyDSIGN EcdsaSecp256k1DSIGN -> ByteString -> SignatureResult
wrongVerificationKey sKey wrongVKey msgBs = do
    let mh = hashAndPack (Proxy @SHA3_256) msgBs 
        signature = signDSIGN () mh sKey
        result = verifyDSIGN () wrongVKey mh signature
    case result of 
        Left err -> (wrongVKey, mh, signature, False) 
        Right _ -> (wrongVKey, mh, signature, True)

wrongMessageRightSignature :: SignKeyDSIGN EcdsaSecp256k1DSIGN -> ByteString -> IO SignatureResult
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

wrongSignatureRightMessage :: SignKeyDSIGN EcdsaSecp256k1DSIGN -> ByteString -> IO SignatureResult
wrongSignatureRightMessage sKey msgBs = do
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

