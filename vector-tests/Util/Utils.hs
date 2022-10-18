{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

module Util.Utils
  ( toHex,
    unHex,
    byteStringToString,
    toHexByteString,
    convertToBytes,
  )
where

import Cardano.Binary (ToCBOR, serialize')
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.ByteString.UTF8 as BSU -- from utf8-string
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

-- Convert raw bytes to base16
toHex :: ToCBOR a => a -> Int -> String
toHex a dropFront = T.unpack $ T.decodeUtf8 $ BS.drop dropFront $ BS16.encode $ serialize' a

--Convert bas16 to raw bytes
unHex :: ByteString -> Either String ByteString
unHex = BS16.decode

-- Convert byteString to String
byteStringToString :: ByteString -> String
byteStringToString = T.unpack . T.decodeUtf8

toHexByteString :: ByteString -> ByteString
toHexByteString = BS16.encode

convertToBytes :: String -> String -> IO ByteString
convertToBytes prefix hexStr = do
  let hexBs = BSU.fromString $ prefix ++ hexStr
  let bytesE = unHex hexBs
  case bytesE of
    Left _ -> error "Error: Couldn't unHex the Hex string. Incorrect format."
    Right bytes' -> pure bytes'
