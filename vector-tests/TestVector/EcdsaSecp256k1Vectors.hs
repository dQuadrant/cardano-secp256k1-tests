{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

{-# HLINT ignore "Use head" #-}

module TestVector.EcdsaSecp256k1Vectors
  ( tests,
    testVectorsIO,
  )
where

-- from utf8-string
import Cardano.Binary (DecoderError (..), decodeFull')
import Cardano.Crypto.DSIGN
  ( DSIGNAlgorithm (..),
    EcdsaSecp256k1DSIGN,
    MessageHash,
    SigDSIGN,
    VerKeyDSIGN,
    fromMessageHash,
    hashAndPack,
    signDSIGN,
    toMessageHash,
    verifyDSIGN,
  )
import Cardano.Crypto.Hash.SHA3_256 (SHA3_256)
import Codec.CBOR.Read (DeserialiseFailure (..))
import Control.Exception (SomeException (..), throw, try)
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.UTF8 as BSU
import qualified Data.Csv as Csv
import Data.List (isInfixOf)
import Data.Proxy (Proxy (..))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, testCase)
import TestVector.Vectors
  ( defaultEcdsaSignature,
    defaultLeftOverValueConvertedForDecoderError,
    defaultMessage,
    defaultSKey,
    defaultVKey,
    ecdsa256k1VKeyAndSigVerifyTestVectors,
    insufficientLengthError,
    signAndVerifyTestVectors,
    vectorsOutputCsvPath,
    wrongLengthMessageHashTestVectors,
    wrongMessagesAndSignaturesTestVectors,
    wrongVerificationKeyTestVectors,
  )
import Util.Utils (convertToBytes, toHex)

tests :: TestTree
tests =
  testGroup
    "EcdsaSecp256k1 Test Vectors"
    [ testCase "Ecdsa Test vectors should run sucessfully and output a csv file." testVectorsIO
    ]

--  skey    vkey    msg     msgHash sig     result
type CsvResult = (String, String, String, String, String, String)

convertResultToCsvRecord :: String -> String -> String -> EcdsaSignatureResult -> CsvResult
convertResultToCsvRecord sKey vKey msg (sig, veriResult) = (sKey, vKey, msg, toHex (fromMessageHash $ hashMessage msg) 4, toHex sig 4, show veriResult)

testVectorsIO :: IO ()
testVectorsIO = do
  -- Vectors for sign and verify for different skeys and messages
  -- Note: Could be replaced with for loop but result gathering might be cumbersome for just 4 repitition
  (sKey1, vKey1, msg1, mh1, sig1, result1) <- signAndVerifyTestVector (signAndVerifyTestVectors !! 0)
  (sKey2, vKey2, msg2, mh2, sig2, result2) <- signAndVerifyTestVector (signAndVerifyTestVectors !! 1)
  (sKey3, vKey3, msg3, mh3, sig3, result3) <- signAndVerifyTestVector (signAndVerifyTestVectors !! 2)
  (sKey4, vKey4, msg4, mh4, sig4, result4) <- signAndVerifyTestVector (signAndVerifyTestVectors !! 3)

  --Vector for verify using already generated signature and public key
  (_, vKey5, msg5, mh5, sig5, result5) <- verifyOnlyTestVector (ecdsa256k1VKeyAndSigVerifyTestVectors !! 0)

  -- --Vectors for wrong length of message hash
  (sKey6, vKey6, _, mh6, _, result6) <- wrongSignMessageHashLengthTestVector (wrongLengthMessageHashTestVectors !! 0)
  (sKey7, vKey7, _, mh7, _, result7) <- wrongSignMessageHashLengthTestVector (wrongLengthMessageHashTestVectors !! 1)
  (sKey8, vKey8, _, mh8, _, result8) <- wrongVerifyMessageHashLengthTestVector (wrongLengthMessageHashTestVectors !! 0)
  (sKey9, vKey9, _, mh9, _, result9) <- wrongVerifyMessageHashLengthTestVector (wrongLengthMessageHashTestVectors !! 1)

  -- --Vector for wrong verification key used to verify using another signature
  (sKey10, vKey10, msg10, mh10, sig10, result10) <- wrongVerificationKeyTestVector (wrongVerificationKeyTestVectors !! 0)

  -- --Vector for verification key used that is not on curve
  (sKey11, vKey11, msg11, mh11, sig11, result11) <- verificationKeyNotOnCurveTestVector (wrongVerificationKeyTestVectors !! 1)

  -- --Vector for wrong message and signatures
  (sKey12, vKey12, msg12, mh12, sig12, result12) <- wrongMessageRightSignatureTestVector (wrongMessagesAndSignaturesTestVectors !! 0)
  (sKey13, vKey13, msg13, mh13, sig13, result13) <- rightMessageWrongSignatureTestVector (wrongMessagesAndSignaturesTestVectors !! 1)

  -- --Vector for invalid verification key length check
  (_, vKey14, msg14, mh14, sig14, result14) <- invalidLengthVerificationKeyTestVector (wrongVerificationKeyTestVectors !! 2)
  (_, vKey15, msg15, mh15, sig15, result15) <- invalidLengthVerificationKeyTestVector (wrongVerificationKeyTestVectors !! 3)

  -- --Vector for invalid signature length check
  (_, vKey16, msg16, mh16, sig16, result16) <- invalidLengthSignatureTestVector (ecdsa256k1VKeyAndSigVerifyTestVectors !! 1)
  (_, vKey17, msg17, mh17, sig17, result17) <- invalidLengthSignatureTestVector (ecdsa256k1VKeyAndSigVerifyTestVectors !! 2)

  let finalResult =
        [ ("index", "secret key", "public key", "message", "message hash", "signature", "verification result", "comment"),
          ("1", sKey1, vKey1, msg1, mh1, sig1, result1, ""),
          ("2", sKey2, vKey2, msg2, mh2, sig2, result2, ""),
          ("3", sKey3, vKey3, msg3, mh3, sig3, result3, ""),
          ("4", sKey4, vKey4, msg4, mh4, sig4, result4, ""),
          ("5", "", vKey5, msg5, mh5, sig5, result5, ""),
          ("6", sKey6, vKey6, "", mh6, "", result6, "Invalid sign message hash length 1 used. Verification should be false."),
          ("7", sKey7, vKey7, "", mh7, "", result7, "Invalid sign message hash length 33 used. Verification should be false."),
          ("8", sKey8, vKey8, "", mh8, "", result8, "Invalid verify message hash length 1 used. Verification should be false."),
          ("9", sKey9, vKey9, "", mh9, "", result9, "Invalid verify message hash length 33 used. Verification should be false."),
          ("10", sKey10, vKey10, msg10, mh10, sig10, result10, "Wrong Verification key is used to verify signature signed by another signing key. Verification should be false."),
          ("11", sKey11, vKey11, msg11, mh11, sig11, result11, "Verification key not on the curve. Verification should be false."),
          ("12", sKey12, vKey12, msg12, mh12, sig12, result12, "Wrong message but right signature used. Verification should be false."),
          ("13", sKey13, vKey13, msg13, mh13, sig13, result13, "Right message but wrong signature is used. Verification should be false."),
          ("14", "", vKey14, msg14, mh14, sig14, result14, "Invalid Verification key length is used. Verification should be false."),
          ("15", "", vKey15, msg15, mh15, sig15, result15, "Invalid Verification key length is used. Verification should be false."),
          ("16", "", vKey16, msg16, mh16, sig16, result16, "Invalid Signature length is used. Verification should be false."),
          ("17", "", vKey17, msg17, mh17, sig17, result17, "Invalid Signature length is used. Verification should be false.")
        ]
  BSL.writeFile (vectorsOutputCsvPath ++ "ecdsa-secp256k1-test-vectors.csv") (Csv.encode finalResult)

--Whole sign and verify flow test vector
signAndVerifyTestVector :: (String, String, String) -> IO CsvResult
signAndVerifyTestVector (sKey, vKey, msg) = do
  result <- ecdsaSignAndVerifyTestVector sKey vKey msg
  pure $ convertResultToCsvRecord sKey vKey msg result

-- Parse exsiting signature and verify using vkey msg and signature only
verifyOnlyTestVector :: (String, String, String, String) -> IO CsvResult
verifyOnlyTestVector (sKeyStr, vKeyStr, msg, sigStr) = do
  result <- verifyOnlyWithSigTestVector sKeyStr vKeyStr msg sigStr
  pure ("", vKeyStr, msg, toHex (fromMessageHash $ hashMessage msg) 4, sigStr, show $ snd result)

-- Pass invalid length message hash in signing stage
wrongSignMessageHashLengthTestVector :: String -> IO CsvResult
wrongSignMessageHashLengthTestVector msg = do
  let invalidMsgHash = toMessageHash $ BSU.fromString msg
  result <- try (ecdsaSignAndVerify defaultSKey defaultVKey Nothing Nothing invalidMsgHash invalidMsgHash Nothing) :: IO (Either SomeException EcdsaSignatureResult)
  case result of
    Left _ -> pure (defaultSKey, defaultVKey, "", msg, "", "False")
    Right _ -> error "Test failed. Sign and verified when using wrong verification message hash length."

-- Pass invalid length message hash in verification stage
wrongVerifyMessageHashLengthTestVector :: String -> IO CsvResult
wrongVerifyMessageHashLengthTestVector msg = do
  let invalidMsgHash = toMessageHash $ BSU.fromString msg
      validMsgHash = hashMessage msg
  result <- try (ecdsaSignAndVerify defaultSKey defaultVKey Nothing Nothing (Just validMsgHash) invalidMsgHash Nothing) :: IO (Either SomeException EcdsaSignatureResult)
  case result of
    Left _ -> pure (defaultSKey, defaultVKey, "", msg, "", "False")
    Right _ -> error "Test failed. Sign and verified when using wrong verification message hash length."

-- Use another verification to verify the message sign by another sign key
wrongVerificationKeyTestVector :: String -> IO CsvResult
wrongVerificationKeyTestVector wrongVKey = do
  result <- ecdsaSignAndVerifyTestVector defaultSKey wrongVKey defaultMessage
  pure $ convertResultToCsvRecord defaultSKey wrongVKey defaultMessage result

-- Use verification key that is not on the curve
verificationKeyNotOnCurveTestVector :: String -> IO CsvResult
verificationKeyNotOnCurveTestVector wrongVKey = do
  result <- try (ecdsaSignAndVerifyTestVector defaultSKey wrongVKey defaultMessage) :: IO (Either DecoderError EcdsaSignatureResult)
  case result of
    Left (DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err)) -> do
      assertBool "Expected cannot decode key error." $ isInfixOf "cannot decode key" err
      pure (defaultSKey, wrongVKey, defaultMessage, toHex (fromMessageHash $ hashMessage defaultMessage) 4, defaultEcdsaSignature, "False")
    Left _ -> error "Test failed. Unexpected verification key decoding error encountered."
    Right _ -> error "Test failed. Sign and verified when using verification not on the curve should not be successful."

-- Sign using one message but verify using another message but right signature
wrongMessageRightSignatureTestVector :: (String, String, String) -> IO CsvResult
wrongMessageRightSignatureTestVector (signMsg, verifyMsg, _) = do
  result <- ecdsaSignAndVerify defaultSKey defaultVKey (Just signMsg) (Just verifyMsg) Nothing Nothing Nothing
  pure $ convertResultToCsvRecord defaultSKey defaultVKey verifyMsg result

-- Sign using one message and verify using same message but wrong signature
rightMessageWrongSignatureTestVector :: (String, String, String) -> IO CsvResult
rightMessageWrongSignatureTestVector (signMsg, verifyMsg, signature) = do
  result <- ecdsaSignAndVerify defaultSKey defaultVKey (Just signMsg) (Just verifyMsg) Nothing Nothing (Just signature)
  pure $ convertResultToCsvRecord defaultSKey defaultVKey signMsg result

-- Use invalid verification key length and try to verify using vkey msg and signature only
invalidLengthVerificationKeyTestVector :: String -> IO CsvResult
invalidLengthVerificationKeyTestVector invalidVKey = do
  result <- try (verifyOnlyWithSigTestVector defaultSKey invalidVKey defaultMessage defaultEcdsaSignature) :: IO (Either DecoderError EcdsaSignatureResult)
  case result of
    Left ex -> do
      case ex of
        DecoderErrorLeftover _ leftOverValue -> do
          assertBool "Error Leftovervalue must be as specified in vectors." $ isInfixOf defaultLeftOverValueConvertedForDecoderError (show leftOverValue)
        DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err) -> do
          assertBool "Expected end of input error." $ isInfixOf insufficientLengthError err
        _ -> error "Test failed. Unexpected signature decoding error encountered."
      pure (defaultSKey, invalidVKey, defaultMessage, toHex (fromMessageHash $ hashMessage defaultMessage) 4, defaultEcdsaSignature, "False")
    Right _ -> error "Test failed. Sign and verified when using verification not on the curve should not be successful."

-- Parse exsiting invalid signature and try to verify using vkey msg and signature only
invalidLengthSignatureTestVector :: (String, String, String, String) -> IO CsvResult
invalidLengthSignatureTestVector (sKeyStr, vKeyStr, msg, sigStr) = do
  result <- try (verifyOnlyWithSigTestVector sKeyStr vKeyStr msg sigStr) :: IO (Either DecoderError EcdsaSignatureResult)
  case result of
    Left ex -> do
      case ex of
        DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err) -> do
          assertBool "Expected end of input error." $ isInfixOf insufficientLengthError err
        DecoderErrorLeftover _ leftOverValue -> do
          assertBool "Error Leftovervalue must be as specified in vectors." $ isInfixOf defaultLeftOverValueConvertedForDecoderError (show leftOverValue)
        _ -> error "Test failed. Unexpected signature decoding error encountered."
      pure ("", vKeyStr, msg, toHex (fromMessageHash $ hashMessage msg) 4, sigStr, "False")
    Right _ -> error "Test failed. Sign and verified when using verification not on the curve should not be successful."

-- Simple sign and verify test vector function with sKey, vKey and message in string
ecdsaSignAndVerifyTestVector :: String -> String -> String -> IO EcdsaSignatureResult
ecdsaSignAndVerifyTestVector sKeyStr vKeyStr signMsg = ecdsaSignAndVerify sKeyStr vKeyStr (Just signMsg) (Just signMsg) Nothing Nothing Nothing

-- Simple verify only test vector with verification message and signature in string
verifyOnlyWithSigTestVector :: String -> String -> String -> String -> IO EcdsaSignatureResult
verifyOnlyWithSigTestVector sKeyStr vKeyStr verifyMsg sig = ecdsaSignAndVerify sKeyStr vKeyStr Nothing (Just verifyMsg) Nothing Nothing (Just sig)

signMessageHashNotPresent :: String
signMessageHashNotPresent = "Sign Message or message hash must be present. Encountered both Nothing."

verifyMessageHashNotPresent :: String
verifyMessageHashNotPresent = "Sign Message or message hash must be present. Encountered both Nothing."

-- Sign and verify flow with optional message hash for sign and verify, optional signature and use them appropriately for sign and verify
ecdsaSignAndVerify :: String -> String -> Maybe String -> Maybe String -> Maybe MessageHash -> Maybe MessageHash -> Maybe String -> IO EcdsaSignatureResult
ecdsaSignAndVerify sKeyStr vKeyStr signMsgM verifyMsgM signHashM verifyHashM sigM = do
  let signMh = case (signMsgM, signHashM) of
        (_, Just msgHash) -> msgHash
        (Just signMsg, Nothing) -> hashMessage signMsg
        (Nothing, Nothing) -> error signMessageHashNotPresent
  let verifyMh = case (verifyMsgM, verifyHashM) of
        (_, Just msgHash) -> msgHash
        (Just verifyMsg, Nothing) -> hashMessage verifyMsg
        (Nothing, Nothing) -> error verifyMessageHashNotPresent
  sig <- case sigM of
    Just sig' -> parseEcdsaSignature sig'
    Nothing -> ecdsaSign sKeyStr signMh
  result <- ecdsaVerify vKeyStr verifyMh sig
  pure (sig, result)

-- Sign the message hash by parsing the sign key in string
ecdsaSign :: String -> MessageHash -> IO (SigDSIGN EcdsaSecp256k1DSIGN)
ecdsaSign sKeyStr mh = do
  sKey <- parseEcdsaSignKey sKeyStr
  pure $ signDSIGN () mh sKey

-- Verify using vKey in string parse it, use message hash and ecdsa signature
-- to verify it and return results
ecdsaVerify :: String -> MessageHash -> SigDSIGN EcdsaSecp256k1DSIGN -> IO Bool
ecdsaVerify vKeyStr mh sig = do
  vKey <- parseEcdsaVerKey vKeyStr
  let result = verifyDSIGN () vKey mh sig
  case result of
    Left _ -> pure False
    Right _ -> pure True

--Hash message using SHA3_256
hashMessage :: String -> MessageHash
hashMessage msg = hashAndPack (Proxy @SHA3_256) $ BSU.fromString msg

-- Convert vKeyInHex to appropirate vKey
parseEcdsaVerKey :: String -> IO (VerKeyDSIGN EcdsaSecp256k1DSIGN)
parseEcdsaVerKey vKeyHex = do
  vKeyBytes <- convertToBytes "582102" vKeyHex
  let vKeyE = decodeFull' vKeyBytes
  case vKeyE of
    Left err -> throw err
    Right vKey -> pure vKey

-- Convert sKeyInHex to appropirate sKey
parseEcdsaSignKey :: String -> IO (SignKeyDSIGN EcdsaSecp256k1DSIGN)
parseEcdsaSignKey sKeyHex = do
  sKeyBytes <- convertToBytes "5820" sKeyHex
  let sKeyE = decodeFull' sKeyBytes
  case sKeyE of
    Left err -> throw err
    Right sKey -> pure sKey

-- Convert sigInHex to appropirate signature
parseEcdsaSignature :: String -> IO (SigDSIGN EcdsaSecp256k1DSIGN)
parseEcdsaSignature sigHex = do
  sigBytes <- convertToBytes "5840" sigHex
  let sigE = decodeFull' sigBytes :: Either DecoderError (SigDSIGN EcdsaSecp256k1DSIGN)
  case sigE of
    Left err -> throw err
    Right sig -> pure sig

-- Holder for signature result with verified true or false
type EcdsaSignatureResult = (SigDSIGN EcdsaSecp256k1DSIGN, Bool)
