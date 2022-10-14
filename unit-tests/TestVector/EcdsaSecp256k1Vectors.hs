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

module TestVector.EcdsaSecp256k1Vectors
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
import Control.Exception(throw)

testClass = "EcdsaSecp256k1Vectors"


defaultSKey = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
defaultVKey = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
defaultMessage = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
-- List of test vectors used row wisely
signAndVerifyTestVectors = [
    -- (secretKey, publicKey, message)
    ("0000000000000000000000000000000000000000000000000000000000000003", "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", "0000000000000000000000000000000000000000000000000000000000000000"),
    ("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
    ("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9", "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8", "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"),
    ("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710", "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")]
vKeyAndSigVerifyTestVector = 
    -- public key, message, signature
    ("599de3e582e2a3779208a210dfeae8f330b9af00a47a7fb22e9bb8ef596f301b","0000000000000000000000000000000000000000000000000000000000000000","354b868c757ef0b796003f7c23dd754d2d1726629145be2c7b7794a25fec80a06254f0915935f33b91bceb16d46ff2814f659e9b6791a4a21ff8764b78d7e114")

wrongLengthMessageHashTestVectors = [
    "0",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
    ]
wrongVerificationKeyTestVectors = [
    "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
    "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"
    ]
wrongMessagesAndSignaturesTestVectors = [
    -- sign message, verify message, message signaure
    ("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",""),
    ("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","354b868c757ef0b796003f7c23dd754d2d1726629145be2c7b7794a25fec80a06254f0915935f33b91bceb16d46ff2814f659e9b6791a4a21ff8764b78d7e114")
    ]

-- tests :: TestTree
-- tests =
--     testGroup "EcdsaSecp256k1 Test" [
--         signAndVerifyTest,
--         invalidLengthMessageHashTest,
--         validLengthMessageHashTest,
--         wrongVerificationKeyTest,
--         wrongMessageSignatureTest
--     ]

              --  skey    vkey    msg     sig     result
type CsvResult = (String, String, String, String, String)

convertResultToCsvRecord :: String -> String -> String -> EcdsaSignatureResult -> CsvResult
convertResultToCsvRecord sKey vKey msg result@(sig, veriResult) = (sKey, vKey, msg, toHex (fromMessageHash $ hashMessage msg) 4, toHex sig 4, show veriResult)

testVectorsIO :: IO ()
testVectorsIO = do
    
    --Vectors for sign and verify for different skeys and messages
    (sKey1,vKey1,msg1,mh1,sig1,result1) <- signVerifyTestVector1
    (sKey2,vKey2,msg2,mh2,sig2,result2) <- signVerifyTestVector2
    (sKey3,vKey3,msg3,mh3,sig3,result3) <- signVerifyTestVector3
    (sKey4,vKey4,msg4,mh4,sig4,result4) <- signVerifyTestVector4

    --Vector for verify using already generated signature and public key
    (vKey5,sig5,result5) <- verifyOnlyTestVector1
    
    --Vectors for wrong length of message hash
    (sKey6,vKey6,mh6,result6) <- wrongSignMessageHashLengthTestVector1
    (sKey7,vKey7,mh7,result7) <- wrongSignMessageHashLengthTestVector2
    (sKey8,vKey8,mh8,result8) <- wrongVerifyMessageHashLengthTestVector1
    (sKey9,vKey9,mh9,result9) <- wrongVerifyMessageHashLengthTestVector2

    --Vector for wrong verification key used to verify using another signature
    (sKey10,vKey10,msg10,mh10,sig10,result10) <- wrongVerificationKeyTestVector1
    --Vector for verification key used that is not on curve
    (sKey11,vKey11,msg11,mh11,sig11,result11) <- verificationKeyNotOnCurveTestVector1
    --Vector for wrong message and signatures
    (sKey12,vKey12,msg12,mh12,sig12,result12) <- wrongMessageRightSignatureTestVector1
    (sKey13,vKey13,msg13,mh13,sig13,result13) <- rightMessageWrongSignatureTestVector1

    let finalResult = [
            ("index", "secret key", "public key", "message", "message hash", "signature", "verification result", "comment"),
            ("1", sKey1, vKey1, msg1, mh1, sig1, result1, ""),
            ("2", sKey2, vKey2, msg2, mh2, sig2, result2, ""),
            ("3", sKey3, vKey3, msg3, mh3, sig3, result3, ""),
            ("4", sKey4, vKey4, msg4, mh4, sig4, result4, ""),
            ("5", "",    vKey5, "",   "",  sig5, result5, ""),
            ("6", sKey6, vKey6, "", mh6, "", result6, "Invalid sign message hash length 1 used. Verification should be false."),
            ("7", sKey7, vKey7, "", mh7, "", result7, "Invalid sign message hash length 33 used. Verification should be false."),
            ("8", sKey8, vKey8, "", mh8, "", result8, "Invalid verify message hash length 1 used. Verification should be false."),
            ("9", sKey9, vKey9, "", mh9, "", result9, "Invalid verify message hash length 33 used. Verification should be false."),
            ("10", sKey10, vKey10, msg10, mh10, sig10, result10, "Wrong Verification key is used to verify signature signed by another signing key. Verification should be false."),
            ("11", sKey11, vKey11, msg11, mh11, sig11, result11, "Verification key not on the curve. Verification should be false."),
            ("12", sKey12, vKey12, msg12, mh12, sig12, result12, "Wrong message but right signature used. Verification should be false."),
            ("13", sKey13, vKey13, msg13, mh13, sig13, result13, "Right message but wrong signature is used. Verification should be false.")
            ]
    BSL.writeFile "ecdsa-secp256k1-test-vectors.csv" $ Csv.encode finalResult

signVerifyTestVector1 :: IO CsvResult
signVerifyTestVector1 = do
    let (sKey,vKey,msg) = signAndVerifyTestVectors !! 0
    result <- signAndVerifyTestVector sKey vKey msg
    pure $ convertResultToCsvRecord sKey vKey msg result

signVerifyTestVector2 :: IO CsvResult
signVerifyTestVector2 = do
    let (sKey,vKey,msg) = signAndVerifyTestVectors !! 1
    result <- signAndVerifyTestVector sKey msg
    pure $ convertResultToCsvRecord sKey vKey msg result

signVerifyTestVector3 :: IO CsvResult
signVerifyTestVector3 = do
    let (sKey,vKey,msg) = signAndVerifyTestVectors !! 2
    result <- signAndVerifyTestVector sKey msg
    pure $ convertResultToCsvRecord sKey vKey msg result

signVerifyTestVector4 :: IO CsvResult
signVerifyTestVector4 = do
    let (sKey,vKey,msg) = signAndVerifyTestVectors !! 3
    result <- signAndVerifyTestVector sKey msg
    pure $ convertResultToCsvRecord sKey vKey msg result

verifyOnlyTestVector1 :: IO CsvResult
verifyOnlyTestVector1 = do
    let (vKeyStr, msg, sigStr) = vKeyAndSigVerifyTestVector
        msgHash = hashMessage msg
    sig <- parseEcdsaSignature sigStr
    result <- verify vKeyStr msgHash sig
    pure (vKeyStr, msgHash, sig, result)

-- Pass invalid length message hash in signing stage
wrongSignMessageHashLengthTestVector1 :: IO CsvResult
wrongSignMessageHashLengthTestVector1 = do
    let msg = head wrongLengthMessageHashTestVectors
        invalidMsgHash = toMessageHash $ BSU.fromString msg
    result <- signAndVerify defaultSKey defaultVKey Nothing Nothing (Just invalidMsgHash) (Just invalidMsgHash) Nothing
    pure (defaultSKey,defaultVKey,msg,)    

-- Pass invalid length message hash in signing stage
wrongSignMessageHashLengthTestVector2 :: IO CsvResult
wrongSignMessageHashLengthTestVector2 = do
    let msg = wrongLengthMessageHashTestVectors !! 1
        invalidMsgHash = toMessageHash $ BSU.fromString msg
    result <- signAndVerify defaultSKey defaultVKey Nothing Nothing (Just invalidMsgHash) (Just invalidMsgHash) Nothing
    pure (defaultSKey,defaultVKey,msg,)

-- Pass invalid length message hash in verification stage
wrongVerifyMessageHashLengthTestVector1 :: IO CsvResult
wrongVerifyMessageHashLengthTestVector1 = do
    let msg = head wrongLengthMessageHashTestVectors
        invalidMsgHash = toMessageHash $ BSU.fromString msg
        validMsgHash = hashMessage msg
    result <- signAndVerify defaultSKey defaultVKey Nothing Nothing (Just validMsgHash) (Just invalidMsgHash) Nothing
    pure (defaultSKey,defaultVKey,msg,)

-- Pass invalid length message hash in verification stage
wrongVerifyMessageHashLengthTestVector2 :: IO CsvResult
wrongVerifyMessageHashLengthTestVector2 = do
    let msg = wrongLengthMessageHashTestVectors !! 1
        invalidMsgHash = toMessageHash $ BSU.fromString msg
        validMsgHash = hashMessage msg

    result <- try (signAndVerify defaultSKey defaultVKey Nothing Nothing (Just validMsgHash) (Just invalidMsgHash) Nothing) :: IO (Either SomeException EcdsaSignatureResult)
    case result of 
        Left ex -> 
        Right result -> error "Test failed. Result "
    pure (defaultSKey,defaultVKey,msg,)

-- Use another verification to verify the message sign by another sign key
wrongVerificationKeyTestVector1 :: IO CsvResult
wrongVerificationKeyTestVector1 = do
    let wrongVKey = head wrongVerificationKeyTestVectors
    result <- signAndVerifyTestVector defaultSKey wrongVKey defaultMessage
    pure $ convertResultToCsvRecord defaultSKey wrongVKey defaultMessage result

-- Use verification key that is not on the curve
verificationKeyNotOnCurveTestVector1 :: IO CsvResult
verificationKeyNotOnCurveTestVector1 = do
    let wrongVKey = wrongVerificationKeyTestVectors !! 1
    result <- signAndVerifyTestVector defaultSKey wrongVKey defaultMessage
    pure $ convertResultToCsvRecord defaultSKey wrongVKey defaultMessage result

-- Sign using one message but verify using another message but right signature
wrongMessageRightSignatureTestVector1 :: IO CsvResult
wrongMessageRightSignatureTestVector1 = do
    let (signMsg,verifyMsg,_) = head wrongMessagesAndSignaturesTestVectors
    result <- signAndVerify defaultSKey defaultVKey (Just signMsg) (Just verifyMsg) Nothing Nothing Nothing
    pure $ convertResultToCsvRecord defaultSKey defaultVKey verifyMsg result

-- Sign using one message and verify using same message but wrong signature
rightMessageWrongSignatureTestVector1 :: IO CsvResult
rightMessageWrongSignatureTestVector1 = do
    let (signMsg,verifyMsg,signature) = wrongMessagesAndSignaturesTestVectors !! 1
    sig <- parseEcdsaSignature signature
    result <- signAndVerify defaultSKey defaultVKey (Just signMsg) (Just verifyMsg) Nothing Nothing (Just sig)
    pure $ convertResultToCsvRecord defaultSKey defaultVKey signMsg result

-- Simple sign and verify test vector function with sKey, vKey and message in string
signAndVerifyTestVector :: String -> String -> String -> IO EcdsaSignatureResult
signAndVerifyTestVector sKeyStr vKeyStr signMsg = signAndVerify sKeyStr vKeyStr (Just signMsg) (Just signMsg) Nothing Nothing Nothing

-- Sign and verify flow with optional message hash for sign and verify, optional signature and use them appropriately for sign and verify 
signAndVerify :: String -> String -> Maybe String -> Maybe String -> Maybe MessageHash -> Maybe MessageHash -> Maybe (SigDSIGN EcdsaSecp256k1DSIGN) -> IO EcdsaSignatureResult
signAndVerify sKeyStr vKeyStr signMsgM verifyMsgM signHashM verifyHashM sigM = do
    let signMh = case (signMsgM, signHashM) of 
                    (_, Just msgHash)-> msgHash
                    (Just signMsg,Nothing) -> hashMessage signMsg
                    (Nothing, Nothing) -> error "Sign Message or message hash must be present. Encountered both Nothing."
    let verifyMh = case (verifyMsgM, verifyHashM) of 
                    (_,Just msgHash)-> msgHash
                    (Just verifyMsg, Nothing) -> hashMessage verifyMsg
                    (Nothing, Nothing) -> error "Verify Message or message hash must be present. Encountered both Nothing."
    sig <- case sigM of
                Just sig' -> pure sig'
                Nothing -> sign sKeyStr signMh
    result <- verify vKeyStr verifyMh sig
    pure (sig, result)

-- Sign the message hash by parsing the sign key in string
sign :: String -> MessageHash-> IO (SigDSIGN EcdsaSecp256k1DSIGN)
sign sKeyStr mh = do
    sKey <- parseEcdsaSignKey sKeyStr
    pure $ signDSIGN () mh sKey

-- Verify using vKey in string parse it, use message hash and ecdsa signature 
-- to verify it and return results
verify :: String -> MessageHash -> SigDSIGN EcdsaSecp256k1DSIGN -> IO Bool
verify vKeyStr mh sig = do
    vKey <- parseEcdsaVerKey vKeyStr
    let result = verifyDSIGN () vKey mh sig
    case result of 
        Left err -> pure False
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
    sigBytes <- convertToBytes "5820" sigHex
    let sigE = decodeFull' sigBytes :: Either DecoderError (SigDSIGN EcdsaSecp256k1DSIGN)
    case sigE of 
        Left err -> throw err
        Right sig -> pure sig

-- Holder for signature result with verified true or false
type EcdsaSignatureResult = (SigDSIGN EcdsaSecp256k1DSIGN, Bool)
