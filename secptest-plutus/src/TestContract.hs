{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE NoImplicitPrelude  #-}
{-# LANGUAGE TemplateHaskell    #-}
{-# OPTIONS_GHC -fno-ignore-interface-pragmas #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE NumericUnderscores#-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
module TestContract where


import GHC.Generics (Generic)
import PlutusTx.Prelude
import Prelude(Show)
import qualified Prelude
import Data.Aeson (FromJSON, ToJSON)

import Plutus.V2.Ledger.Api
import qualified Data.ByteString.Short as SBS
import qualified Data.ByteString.Lazy  as LBS
import Cardano.Api.Shelley (PlutusScript (..), PlutusScriptV2)
import Codec.Serialise ( serialise )
import qualified PlutusTx


type Signature = BuiltinByteString

data SecpTestRedeemer = 
      SecpTestRedeemerWithSig Signature  -- redeem by verifying signature
    | SecpTestSkipRedeemer         -- force redeem utxo without verifying signature (For testing purpose)
    deriving (Generic,Show,Prelude.Eq)
PlutusTx.makeIsDataIndexed ''SecpTestRedeemer [('SecpTestRedeemerWithSig, 0), ('SecpTestSkipRedeemer,1)]


data SecpTestDatum=SecpTestDatum{
    testDatumData :: BuiltinByteString,
    testDatumPubKey :: BuiltinByteString  
  } deriving(Show,Generic)


PlutusTx.makeIsDataIndexed ''SecpTestDatum [('SecpTestDatum, 0)]    


{-# INLINABLE mkValidator #-}
mkValidator ::  SecpTestDatum   -> SecpTestRedeemer -> ScriptContext    -> Bool
mkValidator (SecpTestDatum testDatumData testDatumPubKey)   (SecpTestRedeemerWithSig testDatumSignature) ctx =  
  traceIfFalse 
      "Redeemer doesn't have the correct signature"  
      (verifyEcdsaSecp256k1Signature  testDatumPubKey testDatumData testDatumSignature )

mkValidator _   SecpTestSkipRedeemer ctx = True


{-# INLINABLE mkWrappedValidator #-}
mkWrappedValidator ::  BuiltinData -> BuiltinData -> BuiltinData -> ()
mkWrappedValidator  d r c = check $ mkValidator (parseData d "Invalid data") (parseData r "Invalid redeemer") (parseData  c "InvalidContext")
  where
    parseData md s = case fromBuiltinData  md of
      Just datum -> datum
      Nothing      -> traceError s


testValidator ::   Validator
testValidator = mkValidatorScript  $$(PlutusTx.compile [|| mkWrappedValidator ||] )

testScript ::   Script
testScript  =  unValidatorScript  testValidator

testScriptSBS :: SBS.ShortByteString
testScriptSBS  =  SBS.toShort . LBS.toStrict $ serialise $ testScript

testScriptPlutusV2 ::  PlutusScript PlutusScriptV2
testScriptPlutusV2  = PlutusScriptSerialised $ testScriptSBS

