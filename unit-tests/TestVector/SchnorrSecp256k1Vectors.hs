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
import Test.SchnorrSecp256k1Tests

testClass = "SchnorrSecp256k1Vectors"


-- tests :: TestTree
-- tests =
--     testGroup "SchnorrSecp256k1 Test" [
--         signAndVerifyTest,
--         invalidLengthMessageHashTest,
--         validLengthMessageHashTest,
--         wrongVerificationKeyTest,
--         wrongMessageSignatureTest
--     ]

type CsvResult = (String,String,String,String,String)

convertResultToCsvRecord :: String -> String -> SchnorrSignatureResult -> CsvResult
convertResultToCsvRecord sKey msg result@(vKey, sig, veriResult) = (sKey, toHex vKey 4, msg, toHex sig 4, show veriResult)


testVectorsIO :: IO ()
testVectorsIO = do    
    (sKey1,vKey1,msg1,sig1,result1) <- signVerifyTestVector1
    (sKey2,vKey2,msg2,sig2,result2) <- signVerifyTestVector2
    (sKey3,vKey3,msg3,sig3,result3) <- signVerifyTestVector3
    (sKey4,vKey4,msg4,sig4,result4) <- signVerifyTestVector4
    
    (sKey5,vKey5,msg5,sig5,result5) <- wrongVerificationKeyTestVector1
    (sKey6,vKey6,msg6,result6) <- verificationKeyNotOnCurveTestVector1
    (sKey7,vKey7,msg7,sig7,result7) <- wrongMessageRightSignatureTestVector1
    (sKey8,vKey8,msg8,sig8,result8) <- rightMessageWrongSignatureTestVector1


    let finalResult = [
            ("index", "secret key", "public key", "message", "message hash", "signature", "verification result", "comment"),
            ("1", sKey1, vKey1, msg1, "", sig1, result1, ""),
            ("2", sKey2, vKey2, msg2, "", sig2, result2, ""),
            ("3", sKey3, vKey3, msg3, "", sig3, result3, ""),
            ("4", sKey4, vKey4, msg4, "", sig4, result4, ""),
            ("5", sKey5, vKey5, msg5, "", sig5, result5, "Wrong Verification key is used to verify signature signed by another signing key. Verification should be false."),
            ("6", sKey6, vKey6, msg6, "", "", result6, "Verification key not on the curve. Verification should be false."),
            ("7", sKey7, vKey7, msg7, "", sig7, result7, "Wrong message but right signature used. Verification should be false."),
            ("8", sKey8, vKey8, msg8, "", sig8, result8, "Right message but wrong signature is used. Verification should be false.")
            ]
    print finalResult
    BSL.writeFile "schnorr-secp256k1-test-vectors.csv" $ Csv.encode finalResult

signVerifyTestVector1 :: IO CsvResult
signVerifyTestVector1 = do
    let sKey = "EDF2096014005E578CE620019A83C85F1A843BE00F02A3E7A0E68DE5528D9C3B"
        msg = "0000000000000000000000000000000000000000000000000000000000000000"
    result <- signAndVerifyTestVector sKey msg
    pure $ convertResultToCsvRecord sKey msg result

signVerifyTestVector2 :: IO CsvResult
signVerifyTestVector2 = do
    let sKey = "0000000000000000000000000000000000000000000000000000000000000003"
        msg = "0000000000000000000000000000000000000000000000000000000000000000"
    result <- signAndVerifyTestVector sKey msg
    pure $ convertResultToCsvRecord sKey msg result

signVerifyTestVector3 :: IO CsvResult
signVerifyTestVector3 = do
    let sKey = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
        msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
    result <- signAndVerifyTestVector sKey msg
    pure $ convertResultToCsvRecord sKey msg result

signVerifyTestVector4 :: IO CsvResult
signVerifyTestVector4 = do
    let sKey = "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710"
        msg = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    result <- signAndVerifyTestVector sKey msg
    pure $ convertResultToCsvRecord sKey msg result

wrongVerificationKeyTestVector1 :: IO CsvResult
wrongVerificationKeyTestVector1 = do
    let sKey = "9F432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED240171E"
        wrongVKey = "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9"
        msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
    result <- wrongVerificationKeyTestVector sKey wrongVKey msg
    pure $ convertResultToCsvRecord sKey msg result

verificationKeyNotOnCurveTestVector1 :: IO (String,String,String,String)
verificationKeyNotOnCurveTestVector1 = do
    let sKey = "9F432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED240171E"
        wrongVKey = "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"
        msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
        msgBs = BSU.fromString msg
        mh = fromMessageHash $ hashAndPack (Proxy @SHA3_256) msgBs 
    result <- parseHexVerKeyEither wrongVKey
    pure (sKey,wrongVKey, msg, show result)

wrongMessageRightSignatureTestVector1 :: IO CsvResult
wrongMessageRightSignatureTestVector1 = do
    let sKeyStr = "9F432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED240171E"
        msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
        msg2 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        msgBs = BSU.fromString msg
        msgBs2 = BSU.fromString msg2
    sKey <- parseHexSignKey sKeyStr
    result <- wrongMessageRightSignature sKey msgBs msgBs2
    pure $ convertResultToCsvRecord sKeyStr msg2 result

rightMessageWrongSignatureTestVector1 :: IO CsvResult
rightMessageWrongSignatureTestVector1 = do
    let sKeyStr = "9F432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED240171E"
        msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
        msgBs = BSU.fromString $ "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
    sKey <- parseHexSignKey sKeyStr
    result <- rightMessageWrongSignature sKey msgBs
    pure $ convertResultToCsvRecord sKeyStr msg result

wrongVerificationKeyTestVector :: String -> String -> String -> IO SchnorrSignatureResult
wrongVerificationKeyTestVector sKeyStr wrongVKeyStr msg = do
    let msgBs = BSU.fromString msg
    sKey <- parseHexSignKey sKeyStr
    wrongVKey <- parseHexVerKey wrongVKeyStr
    pure $ wrongVerificationKey sKey wrongVKey msgBs

signAndVerifyTestVector :: String -> String -> IO SchnorrSignatureResult
signAndVerifyTestVector sKeyStr msg = do
    let msgBs = BSU.fromString msg
    sKey <- parseHexSignKey sKeyStr
    pure $ signAndVerify sKey msgBs

parseHexVerKeyEither :: String -> IO Bool
parseHexVerKeyEither vKeyHex = do
    vKeyBytes <- convertToBytes "5820" vKeyHex
    let vKeyE = decodeFull' vKeyBytes :: Either DecoderError (VerKeyDSIGN SchnorrSecp256k1DSIGN)
    case vKeyE of 
        Left _ -> pure False
        Right vKey -> pure True
