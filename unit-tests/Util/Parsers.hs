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

module Util.Parsers
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
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.UTF8 as BSU      -- from utf8-string
import Data.Typeable (typeOf)
import Data.Proxy (Proxy (..))
import Cardano.Crypto.Seed(readSeedFromSystemEntropy)
import Data.ByteString.Random (random)
import Cardano.Binary (FromCBOR(fromCBOR), ToCBOR(toCBOR), serialize', decodeFull',DecoderError)
import Util.Utils

type SignatureResult = (VerKeyDSIGN EcdsaSecp256k1DSIGN, MessageHash, SigDSIGN EcdsaSecp256k1DSIGN, Bool)

convertToBytes :: String -> String -> IO ByteString
convertToBytes prefix hexStr = do 
    let hexBs = BSU.fromString $ prefix ++ hexStr
    let bytesE = unHex hexBs
    case bytesE of
        Left _ -> error "Error: Couldn't unHex the Hex string. Incorrect format."
        Right bytes' -> pure bytes'
