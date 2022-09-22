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

module Main
where

import qualified EcdsaSecp256k1Tests as EcdsaSecp256k1Tests
import qualified SchnorrSecp256k1Tests as SchnorrSecp256k1Tests
import GHC.IO.Handle.FD (stdout)
import System.IO (BufferMode (NoBuffering), hSetBuffering)

main :: IO ()
main = do
    hSetBuffering stdout NoBuffering
    putStrLn "\ESC[32m"
    EcdsaSecp256k1Tests.tests
    putStrLn "\n----------------------------------------------------------------------------------------"
    SchnorrSecp256k1Tests.tests



