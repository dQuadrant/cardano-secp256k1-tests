{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -Wno-redundant-constraints #-}
{-# OPTIONS_GHC -Wno-unused-imports #-}

module Util.StringConstants
  ( vectorsOutputCsvPath,
    invalidEcdsaSignatureLengthError,
    invalidSchnorrVerificationKeyLengthError,
    invalidEcdsaVerificationKeyLengthError,
    invalidSchnorrSignatureLengthError,
    cannotDecodeVerificationKeyError,
    unexpectedDecodingError,
  )
where

import Cardano.Crypto.SECP256K1.Constants
  ( SECP256K1_ECDSA_MESSAGE_BYTES,
    SECP256K1_ECDSA_PUBKEY_BYTES,
    SECP256K1_ECDSA_SIGNATURE_BYTES,
    SECP256K1_SCHNORR_PUBKEY_BYTES,
    SECP256K1_SCHNORR_SIGNATURE_BYTES,
  )
import Data.Data (Proxy (Proxy))
import GHC.TypeLits (natVal)
import Util.Utils (hexLength)

vectorsOutputCsvPath :: String
vectorsOutputCsvPath = "vector-tests/csv-outputs/"

invalidEcdsaVerificationKeyLengthError :: String -> String
invalidEcdsaVerificationKeyLengthError = invalidVerificationKeyLengthError $ natVal $ Proxy @SECP256K1_ECDSA_PUBKEY_BYTES

invalidSchnorrVerificationKeyLengthError :: String -> String
invalidSchnorrVerificationKeyLengthError = invalidVerificationKeyLengthError $ natVal $ Proxy @SECP256K1_SCHNORR_PUBKEY_BYTES

invalidVerificationKeyLengthError :: Integer -> String -> String
invalidVerificationKeyLengthError expectedLength actualKey = "decodeVerKeyDSIGN: wrong length, expected " ++ show expectedLength ++ " bytes but got " ++ show (hexLength actualKey)

invalidEcdsaSignatureLengthError :: String -> String
invalidEcdsaSignatureLengthError = invalidSignatureLengthError $ natVal $ Proxy @SECP256K1_ECDSA_SIGNATURE_BYTES

invalidSchnorrSignatureLengthError :: String -> String
invalidSchnorrSignatureLengthError = invalidSignatureLengthError $ natVal $ Proxy @SECP256K1_SCHNORR_SIGNATURE_BYTES

invalidSignatureLengthError :: Integer -> String -> String
invalidSignatureLengthError expectedLength actualSig = "decodeSigDSIGN: wrong length, expected " ++ show expectedLength ++ " bytes but got " ++ show (hexLength actualSig)

cannotDecodeVerificationKeyError :: String
cannotDecodeVerificationKeyError = "decodeVerKeyDSIGN: cannot decode key"

unexpectedDecodingError :: String
unexpectedDecodingError = "Test failed. Unexpected decoding error encountered."