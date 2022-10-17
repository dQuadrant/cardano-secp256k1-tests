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

import qualified Test.EcdsaSecp256k1Tests as EcdsaSecp256k1Tests
import qualified TestVector.EcdsaSecp256k1Vectors as EcdsaSecp256k1Vectors
import qualified Test.SchnorrSecp256k1Tests as SchnorrSecp256k1Tests
import qualified TestVector.SchnorrSecp256k1Vectors as SchnorrSecp256k1Vectors
import GHC.IO.Handle.FD (stdout)
import System.IO (BufferMode (NoBuffering), hSetBuffering)

main :: IO ()
main = do
    hSetBuffering stdout NoBuffering
    putStrLn "\ESC[32m"
    EcdsaSecp256k1Vectors.testVectorsIO
    putStrLn "\n----------------------------------------------------------------------------------------"
    SchnorrSecp256k1Vectors.testVectorsIO




