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

module EcdsaSecp256k1Tests
where

import Cardano.Crypto.DSIGN (
  EcdsaSecp256k1DSIGN,
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

import     Cardano.Crypto.Hash.SHA3_256 (SHA3_256)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.UTF8 as BSU      -- from utf8-string
import Data.Typeable (typeOf)
import Data.Proxy (Proxy (..))

import Cardano.Crypto.Seed(readSeedFromSystemEntropy)

import Data.ByteString.Random (random)

testClass = "EcdsaSecp256k1"

getSignKey :: IO (SignKeyDSIGN EcdsaSecp256k1DSIGN)
getSignKey = do
    seed <- readSeedFromSystemEntropy 32
    pure $ genKeyDSIGN seed

signAndVerifyTest :: IO ()
signAndVerifyTest = do
    sKey <- getSignKey
    msgBs <- random 64
    let mh = hashAndPack (Proxy @SHA3_256) msgBs 
        signature = signDSIGN () mh sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey mh signature
    case result of 
        Left err -> error $ testClass ++ ": signAndVerifyTest: Failed: Couldn't verify the signature."
        Right _ -> putStrLn $ "\n"++testClass++": signAndVerifyTest: Working: Signed and verified successfully.\n"

invalidLengthMessageHashTest:: IO ()
invalidLengthMessageHashTest = do
    sKey <- getSignKey
    let mh = toMessageHash $ BSU.fromString $ ""
    case mh of
        Nothing -> putStrLn $ "\n"++testClass++": invalidLengthMessageHashTest: Working: Invalid message hash length used error thrown which is expected.\n"
        Just _ -> error $ testClass ++ ": invalidLengthMessageHashTest: Failed: toMessageHash function is accepting bytestring other than lenght 32."

validLengthMessageHashTest:: IO ()
validLengthMessageHashTest = do
    sKey <- getSignKey
    bs32 <- random 32
    let mh = toMessageHash $ bs32
    case mh of
        Nothing -> error $ testClass ++ ": toMessageHash function failed it shouldn't be as correct length is provided."
        Just _ -> putStrLn $ "\n"++testClass++": validLengthMessageHashTest: Working: length 32 is accepted.\n"

wrongVerificationKeyTest :: IO ()
wrongVerificationKeyTest = do
    sKey <- getSignKey
    sKey2 <- getSignKey
    msgBs <- random 64
    let mh = hashAndPack (Proxy @SHA3_256) msgBs 
        signature = signDSIGN () mh sKey
        vKey = deriveVerKeyDSIGN sKey2
        result = verifyDSIGN () vKey mh signature
    case result of 
        Left err -> putStrLn $ "\n" ++testClass ++ ": wrongVerificationKeyTest: Working: Error Couldn't verify the signature which is expected. Actual error: " ++ err
        Right _ -> error $ "\n" ++testClass++": wrongVerificationKeyTest: Failed: Signed and verified successfully which is not expected.\n"

wrongMessageSignatureTest :: IO ()
wrongMessageSignatureTest = do
    sKey <- getSignKey
    msgBs <- random 64
    msgBs' <- random 64
    let mh = hashAndPack (Proxy @SHA3_256) msgBs 
    let mh2 = hashAndPack (Proxy @SHA3_256) msgBs'
        signature = signDSIGN () mh sKey
        vKey = deriveVerKeyDSIGN sKey
        result = verifyDSIGN () vKey mh2 signature
    case result of 
        Left err -> putStrLn $ "\n" ++testClass ++ ": wrongMessageSignatureTest: Working: Error Couldn't verify the signature which is expected. Actual error: " ++ err
        Right _ -> error $ "\n" ++testClass++": wrongMessageSignatureTest: Failed: Signed and verified successfully which is not expected.\n"



tests :: IO ()
tests = do
    signAndVerifyTest
    invalidLengthMessageHashTest
    validLengthMessageHashTest
    wrongVerificationKeyTest
    wrongMessageSignatureTest
