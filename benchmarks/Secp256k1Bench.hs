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

module Secp256k1Bench
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
import Test.Tasty hiding (defaultMain)
import Test.Tasty.HUnit
import Cardano.Crypto.Hash.SHA3_256 (SHA3_256)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.UTF8 as BSU      -- from utf8-string
import Data.Typeable (typeOf)
import Data.Proxy (Proxy (..))
import Cardano.Crypto.Seed(readSeedFromSystemEntropy)
import Data.ByteString.Random (random)
import Test.Tasty.Bench

runSecp256k1Bench :: IO ()
runSecp256k1Bench = do
  ecSKey <- getEcdsaSignKey
  scSKey <- getSchnorrSignKey
  msgBs <- random 64
  shortMsgBs <- random 32
  longMsgBs <- random 1048576
  let ecVKey = deriveVerKeyDSIGN ecSKey
      scVKey = deriveVerKeyDSIGN scSKey
      mh = hashAndPack (Proxy @SHA3_256) msgBs 
      ecdsaSig = ecdsaSign ecSKey mh
      schnorrShortMsgSig = schnorrSign scSKey shortMsgBs
      schnorrLongMsgSig = schnorrSign scSKey longMsgBs
  defaultMain
    [
      bgroup "Secp-256k1 benchmarks"
        [
          bench "Ecdsa Sign" $ nf (ecdsaSign ecSKey) mh,
          bench "Ecdsa Verify" $ nf (ecdsaVerify ecVKey mh) ecdsaSig,
          bench "Schnorr Short Message Sign" $ nf (schnorrSign scSKey) shortMsgBs,
          bench "Schnorr Short Message Verify" $ nf (schnorrVerify scVKey shortMsgBs) schnorrShortMsgSig,
          bench "Schnorr Long Message Sign" $ nf (schnorrSign scSKey) longMsgBs,
          bench "Schnorr Long Message Verify" $ nf (schnorrVerify scVKey longMsgBs) schnorrLongMsgSig
        ]
    ]

  putStrLn "Finished....."

getEcdsaSignKey :: IO (SignKeyDSIGN EcdsaSecp256k1DSIGN)
getEcdsaSignKey = do
    seed <- readSeedFromSystemEntropy 32
    pure $ genKeyDSIGN seed


ecdsaSign :: SignKeyDSIGN EcdsaSecp256k1DSIGN -> MessageHash -> SigDSIGN EcdsaSecp256k1DSIGN
ecdsaSign sKey mh = signDSIGN () mh sKey

--Raw verifiction without hashing message first for this raw bench otherwise one should always hash the message first before verification
ecdsaVerify :: VerKeyDSIGN EcdsaSecp256k1DSIGN -> MessageHash -> SigDSIGN EcdsaSecp256k1DSIGN -> ()
ecdsaVerify vKey mh sig = let result = verifyDSIGN () vKey mh sig in
    case result of 
        Left err -> error "Verification failed."
        Right _ -> ()


getSchnorrSignKey :: IO (SignKeyDSIGN SchnorrSecp256k1DSIGN)
getSchnorrSignKey = do
    seed <- readSeedFromSystemEntropy 32
    pure $ genKeyDSIGN seed


schnorrSign :: SignKeyDSIGN SchnorrSecp256k1DSIGN -> ByteString -> SigDSIGN SchnorrSecp256k1DSIGN
schnorrSign sKey msg = signDSIGN () msg sKey

--Raw verifiction without hashing message first for this raw bench otherwise one should always hash the message first before verification
schnorrVerify :: VerKeyDSIGN SchnorrSecp256k1DSIGN -> ByteString -> SigDSIGN SchnorrSecp256k1DSIGN -> ()
schnorrVerify vKey msg sig = let result = verifyDSIGN () vKey msg sig in
    case result of 
        Left err -> error "Verification failed."
        Right _ -> ()
