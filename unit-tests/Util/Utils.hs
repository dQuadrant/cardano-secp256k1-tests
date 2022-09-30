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
{-# LANGUAGE FlexibleContexts #-}


module Util.Utils
where

import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import Cardano.Binary (ToCBOR, serialize')
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
