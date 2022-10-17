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

module TestVector.SchnorrSecp256k1Vectors
where

import Cardano.Crypto.DSIGN (
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
import  Cardano.Crypto.Hash.SHA3_256 (SHA3_256)
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
import Data.Either (isRight)
import Control.Exception(throw,SomeException(..),try)
import TestVector.Vectors
import Data.List (isInfixOf)
import Codec.CBOR.Read (DeserialiseFailure(..))


              --  skey    vkey    msg     sig     result
type CsvResult = (String, String, String, String, String)

convertResultToCsvRecord :: String -> String -> String -> SchnorrSignatureResult -> CsvResult
convertResultToCsvRecord sKey vKey msg result@(sig, veriResult) = (sKey, vKey, msg, toHex sig 4, show veriResult)

testVectorsIO :: IO ()
testVectorsIO = do    
    -- Vectors for sign and verify for different skeys and messages
    -- Note: Could be replaced with for loop but result gathering might be cumbersome for just 4 repitition
    (sKey1,vKey1,msg1,sig1,result1) <- signAndVerifyTestVector (signAndVerifyTestVectors !! 0)
    (sKey2,vKey2,msg2,sig2,result2) <- signAndVerifyTestVector (signAndVerifyTestVectors !! 1)
    (sKey3,vKey3,msg3,sig3,result3) <- signAndVerifyTestVector (signAndVerifyTestVectors !! 2)
    (sKey4,vKey4,msg4,sig4,result4) <- signAndVerifyTestVector (signAndVerifyTestVectors !! 3)
    
    -- Vector for verify using already generated signature and public key
    (_,vKey5,msg5,sig5,result5) <- verifyOnlyTestVector (schnorr256k1VKeyAndSigVerifyTestVectors !! 0)

    -- Vector for wrong verification key used to verify using another signature
    (sKey6,vKey6,msg6,sig6,result6) <- wrongVerificationKeyTestVector (wrongVerificationKeyTestVectors !! 0)

    --Vector for verification key used that is not on curve
    (_,vKey7,msg7,sig7,result7) <- verificationKeyNotOnCurveTestVector (wrongVerificationKeyTestVectors !! 1)

    -- Vector for wrong message and signatures
    (sKey8,vKey8,msg8,sig8,result8) <- wrongMessageRightSignatureTestVector (wrongMessagesAndSignaturesTestVectors !! 0)
    (sKey9,vKey9,msg9,sig9,result9) <- rightMessageWrongSignatureTestVector (wrongMessagesAndSignaturesTestVectors !! 1)

    -- Vector for invalid verification key length check
    (_,vKey10,msg10,sig10,result10)<- invalidLengthVerificationKeyTestVector (wrongVerificationKeyTestVectors !! 2)
    (_,vKey11,msg11,sig11,result11)<- invalidLengthVerificationKeyTestVector (wrongVerificationKeyTestVectors !! 3)

    -- Vector for invalid signature length check
    (_,vKey12,msg12,sig12,result12)<- invalidLengthSignatureTestVector (schnorr256k1VKeyAndSigVerifyTestVectors !! 1)
    (_,vKey13,msg13,sig13,result13)<- invalidLengthSignatureTestVector (schnorr256k1VKeyAndSigVerifyTestVectors !! 2)

    let finalResult = [
            ("index", "secret key", "public key", "message", "message hash", "signature", "verification result", "comment"),
            ("1", sKey1, vKey1, msg1, "", sig1, result1, ""),
            ("2", sKey2, vKey2, msg2, "", sig2, result2, ""),
            ("3", sKey3, vKey3, msg3, "", sig3, result3, ""),
            ("4", sKey4, vKey4, msg4, "", sig4, result4, ""),
            ("5", "",    vKey5, msg5, "", sig5, result5, ""),
            ("6", sKey6, vKey6, msg6, "", sig6, result6, "Wrong Verification key is used to verify signature signed by another signing key. Verification should be false."),
            ("7", "",    vKey7, msg7, "", sig7,   result7, "Verification key not on the curve. Verification should be false."),
            ("8", sKey8, vKey8, msg8, "", sig8, result8, "Wrong message but right signature used. Verification should be false."),
            ("9", sKey9, vKey9, msg9, "", sig9, result9, "Right message but wrong signature is used. Verification should be false."),
            ("10", "",   vKey10, msg10, "", sig10, result10, "Invalid verification key length is used. Verification should be false."),
            ("11", "",   vKey11, msg11, "", sig11, result11, "Invalid verification key length is used. Verification should be false."),
            ("12", "",   vKey12, msg12, "", sig12, result12, "Invalid signature length is used. Verification should be false."),
            ("13", "",   vKey13, msg13, "", sig13, result13, "Invalid signature length is used. Verification should be false.")
            ]
    BSL.writeFile "schnorr-secp256k1-test-vectors.csv" $ Csv.encode finalResult

    print "Done"

--Whole sign and verify flow test vector
signAndVerifyTestVector :: (String, String, String) -> IO CsvResult
signAndVerifyTestVector (sKey, vKey, msg) = do
    result <- schnorrSignAndVerifyTestVector sKey vKey msg
    pure $ convertResultToCsvRecord sKey vKey msg result

-- Parse exsiting signature and verify using vkey msg and signature only
verifyOnlyTestVector :: (String,String,String,String) -> IO CsvResult
verifyOnlyTestVector (sKeyStr, vKeyStr, msg, sigStr)= do
    result <- verifyOnlyWithSigTestVector sKeyStr vKeyStr msg sigStr
    pure (sKeyStr,vKeyStr, msg, sigStr, show $ snd result)

-- Use another verification to verify the message sign by another sign key
wrongVerificationKeyTestVector :: String -> IO CsvResult
wrongVerificationKeyTestVector wrongVKey = do
    result <- schnorrSignAndVerifyTestVector defaultSKey wrongVKey defaultMessage
    pure $ convertResultToCsvRecord defaultSKey wrongVKey defaultMessage result

-- Use verification key that is not on the curve
verificationKeyNotOnCurveTestVector :: String -> IO CsvResult
verificationKeyNotOnCurveTestVector wrongVKey = do
    result <- try (verifyOnlyWithSigTestVector defaultSKey wrongVKey defaultMessage defaultSchnorrSignature) :: IO (Either SomeException SchnorrSignatureResult)
    case result of
        Left err -> pure $ (defaultSKey, wrongVKey, defaultMessage, defaultSchnorrSignature,"False")
        Right result' -> error "Test failed. Sign and verified when using verification not on the curve should not be successful."

-- Sign using one message but verify using another message but right signature
wrongMessageRightSignatureTestVector :: (String,String,String) -> IO CsvResult
wrongMessageRightSignatureTestVector (signMsg,verifyMsg,_) = do
    result <- schnorrSignAndVerify defaultSKey defaultVKey signMsg verifyMsg Nothing
    pure $ convertResultToCsvRecord defaultSKey defaultVKey verifyMsg result

-- Sign using one message and verify using same message but wrong signature
rightMessageWrongSignatureTestVector :: (String,String,String) -> IO CsvResult
rightMessageWrongSignatureTestVector (signMsg,verifyMsg,signature) = do
    result <- schnorrSignAndVerify defaultSKey defaultVKey signMsg verifyMsg (Just signature)
    pure $ convertResultToCsvRecord defaultSKey defaultVKey signMsg result

-- Use invalid verification key length and try to verify using vkey msg and signature only
invalidLengthVerificationKeyTestVector :: String -> IO CsvResult
invalidLengthVerificationKeyTestVector invalidVKey = do
    result <- try (verifyOnlyWithSigTestVector defaultSKey invalidVKey defaultMessage defaultSchnorrSignature) :: IO (Either DecoderError SchnorrSignatureResult)
    case result of 
        Left ex -> do
            case ex of 
                DecoderErrorLeftover _ leftOverValue -> do
                    assertBool "Error Leftovervalue must be as specified in vectors."  $ isInfixOf defaultLeftOverValueConvertedForDecoderError (show leftOverValue)
                DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err) -> do
                    assertBool "Expected end of input error." $ isInfixOf insufficientLengthError  err
            pure $ (defaultSKey, invalidVKey, defaultMessage, defaultSchnorrSignature,"False")
        Right result' -> error "Test failed. Sign and verified when using verification not on the curve should not be successful."

-- Parse exsiting invalid signature and try to verify using vkey msg and signature only
invalidLengthSignatureTestVector :: (String,String,String,String) -> IO CsvResult
invalidLengthSignatureTestVector (sKeyStr, vKeyStr, msg, sigStr) = do
    result <- try (verifyOnlyWithSigTestVector sKeyStr vKeyStr msg sigStr) :: IO (Either DecoderError SchnorrSignatureResult)
    case result of
        Left ex -> do
            case ex of 
                DecoderErrorLeftover _ leftOverValue -> do
                    assertBool "Error Leftovervalue must be as specified in vectors."  $ isInfixOf defaultLeftOverValueConvertedForDecoderError (show leftOverValue)
                DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err) -> do
                    assertBool "Expected end of input error." $ isInfixOf insufficientLengthError  err
            pure (sKeyStr,vKeyStr, msg, sigStr, "False")
        Right result' -> error "Test failed. Sign and verified when using verification not on the curve should not be successful."

-- Simple sign and verify test vector function with sKey, vKey and message in string
schnorrSignAndVerifyTestVector :: String -> String -> String -> IO SchnorrSignatureResult
schnorrSignAndVerifyTestVector sKeyStr vKeyStr signMsg = schnorrSignAndVerify sKeyStr vKeyStr signMsg signMsg Nothing

-- Simple verify only test vector with verification message and signature in string
verifyOnlyWithSigTestVector :: String -> String -> String -> String -> IO SchnorrSignatureResult
verifyOnlyWithSigTestVector sKeyStr vKeyStr verifyMsg sig = schnorrSignAndVerify sKeyStr vKeyStr verifyMsg verifyMsg (Just sig)

-- Sign and verify flow with optional message hash for sign and verify, optional signature and use them appropriately for sign and verify 
schnorrSignAndVerify :: String -> String -> String -> String -> Maybe String -> IO SchnorrSignatureResult
schnorrSignAndVerify sKeyStr vKeyStr signMsg verifyMsg sigM = do
    sig <- case sigM of
                Just sig' -> parseSchnorrSignature sig'
                Nothing -> schnorrSign sKeyStr signMsg
    result <- schnorrVerify vKeyStr verifyMsg sig
    pure (sig, result)

-- Sign the message hash by parsing the sign key in string
schnorrSign :: String -> String-> IO (SigDSIGN SchnorrSecp256k1DSIGN)
schnorrSign sKeyStr msg = do
    sKey <- parseSchnorrSignKey sKeyStr
    pure $ signDSIGN () (BSU.fromString msg) sKey

-- Verify using vKey in string parse it, use message hash and signature 
-- to verify it and return results
schnorrVerify :: String -> String -> SigDSIGN SchnorrSecp256k1DSIGN -> IO Bool
schnorrVerify vKeyStr msg sig = do
    vKey <- parseSchnorrVerKey vKeyStr
    let result = verifyDSIGN () vKey (BSU.fromString msg) sig
    case result of 
        Left err -> pure False
        Right _ -> pure True

-- Convert vKeyInHex to appropirate vKey
parseSchnorrVerKey :: String -> IO (VerKeyDSIGN SchnorrSecp256k1DSIGN)
parseSchnorrVerKey vKeyHex = do
    vKeyBytes <- convertToBytes "5820" vKeyHex
    let vKeyE = decodeFull' vKeyBytes
    case vKeyE of 
        Left err -> throw err
        Right vKey -> pure vKey

-- Convert sKeyInHex to appropirate sKey
parseSchnorrSignKey :: String -> IO (SignKeyDSIGN SchnorrSecp256k1DSIGN)
parseSchnorrSignKey sKeyHex = do
    sKeyBytes <- convertToBytes "5820" sKeyHex
    let sKeyE = decodeFull' sKeyBytes
    case sKeyE of 
        Left err -> throw err
        Right sKey -> pure sKey

-- Convert sigInHex to appropirate signature
parseSchnorrSignature :: String -> IO (SigDSIGN SchnorrSecp256k1DSIGN)
parseSchnorrSignature sigHex = do
    sigBytes <- convertToBytes "5840" sigHex
    let sigE = decodeFull' sigBytes :: Either DecoderError (SigDSIGN SchnorrSecp256k1DSIGN)
    case sigE of 
        Left err -> throw err
        Right sig -> pure sig

-- Holder for signature result with verified true or false
type SchnorrSignatureResult = (SigDSIGN SchnorrSecp256k1DSIGN, Bool)
