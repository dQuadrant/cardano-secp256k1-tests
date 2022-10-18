{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}
module Main
where
import qualified TestContract(testScriptPlutusV2, SecpTestDatum (SecpTestDatum))
import Cardano.Api (serialiseToTextEnvelope, Script (PlutusScript), prettyPrintJSON, NetworkId (Mainnet), getTxId, TxIx (TxIx), hashScript)
import Cardano.Api.Shelley (PlutusScriptVersion(PlutusScriptV2), fromPlutusData)
import qualified Data.Aeson as A
import qualified Data.ByteString.Lazy.Char8 as BS8
import Data.Data (Data)
import Data.Typeable (Typeable)
import System.Console.CmdArgs
import Cardano.Kuber.Api
import Cardano.Kuber.Data.Parsers (parseSignKey, parseAddress)
import Data.Text (Text)
import qualified Data.Text.IO as T
import qualified Data.ByteString.Char8 as BS
import Cardano.Crypto.DSIGN
    ( MessageHash,
      DSIGNAlgorithm(signDSIGN, SigDSIGN, SignKeyDSIGN,
                     deriveVerKeyDSIGN, genKeyDSIGN, VerKeyDSIGN, rawSerialiseSignKeyDSIGN, rawSerialiseVerKeyDSIGN, rawSerialiseSigDSIGN),
      EcdsaSecp256k1DSIGN, hashAndPack, fromMessageHash, verifyDSIGN, toMessageHash )
import Cardano.Crypto.Seed (readSeedFromSystemEntropy)
import Data.ByteString.Random (random)
import Cardano.Kuber.Util (toHexString)
import TestContract (testDatumData, SecpTestDatum (testDatumPubKey), SecpTestRedeemer (SecpTestRedeemerWithSig, SecpTestSkipRedeemer))
import Plutus.V2.Ledger.Api (toBuiltin)
import Codec.Serialise (serialise)
import PlutusTx.IsData (toData)
import Cardano.Binary (toCBOR, serialize')
import qualified Data.ByteString.Lazy as BSL
import Control.Exception (throw)
import Cardano.Api (getTxBody)
import qualified TestContract as TextContract
import Cardano.Crypto.Hash (hashFromBytes)
import Cardano.Crypto.Hash.SHA3_256 (SHA3_256)
import Data.Typeable (Proxy(..))
import Cardano.Api (TxIn(..), ExecutionUnits (ExecutionUnits), makeShelleyAddress, PaymentCredential (PaymentCredentialByScript), StakeAddressReference (NoStakeAddress), shelleyAddressInEra)
import Control.Concurrent (threadDelay)
import Data.ByteString (ByteString)
import PlutusTx.Builtins (verifyEd25519Signature, verifyEcdsaSecp256k1Signature)

data Modes =
      Emulate {
        signKeyFile:: String,
        address :: Maybe Text,
        noPreVerify:: Bool, -- when set, doesn't test the plutus tx function from haskell.
        forceRedeem :: Bool -- when set, tries using redeemer 1 that doesn't verify signature.
    }
    |   Cat
      deriving (Show, Data, Typeable)

main=runCli

runCli :: IO ()
runCli = do
    op <- cmdArgs $ modes [
        Emulate{
            signKeyFile = def &=typ "SignkeyFilePath" ,
            address = def &=typ "WalletAddress",
            noPreVerify = False &=typ "Pre-Verify",
            forceRedeem = False &=typ "UseReddemer1"
        }
        ,Cat
        ]

    case op of
      Emulate signkeyFile mAddr noPreVerify forceRedeem -> do
        sKey<- T.readFile signkeyFile >>= parseSignKey
        walletConstraint<- case mAddr of
          Nothing -> pure $ txWalletSignKey sKey
          Just s -> do
            addr <- parseAddress s
            pure $ txWalletAddress addr
                    <> txWalletSignKey sKey
        nodeInfo <- chainInfoFromEnv >>=withDetails
        ecdsaSignKey <- genEcdsaSignKey
        randomMessage <-   random 32
        let messageHashNative =  hashAndPack (Proxy @SHA3_256) randomMessage
            messageHashBs = fromMessageHash messageHashNative
            ecdsaVkey = deriveVerKeyDSIGN ecdsaSignKey
            signedData = ecdsaSign ecdsaSignKey messageHashNative

        putStrLn $ "secp256k1 SignKey:" ++ show ecdsaSignKey
        putStrLn $ "messageHash: " ++ toHexString messageHashBs
        let lockedDatum = TestContract.SecpTestDatum {
                testDatumData = toBuiltin  messageHashBs
              , testDatumPubKey = toBuiltin $  serialiseVkey ecdsaVkey
              }
            tx1Builder = walletConstraint <> txPayToScriptWithData scriptAddr  mempty (fromPlutusData $ toData lockedDatum)
        
        -- STEP0: preverify that the ecdsaVerify function imported from plutus returns true
        if  noPreVerify  || secp25k1Verify (serialiseVkey ecdsaVkey) messageHashBs (serialiseSignature signedData)
          then pure()
          else do
              putStrLn $ "ecdsaVerify " ++ toHexString (serialiseVkey ecdsaVkey) ++ " " ++ toHexString  messageHashBs ++ " " ++ toHexString (serialiseSignature signedData)
              fail "Error pre-validating signature using plutus function"

         -- STEP1:  lock minAda to the contract with the redeemer containing signedData

        putStrLn $ "Step1: Lock funds to the contract :"
        BS.putStrLn  $ prettyPrintJSON tx1Builder
        txId1<- performSubmission  nodeInfo tx1Builder
        putStrLn $ "Waiting 10 seconds for transaction confirmation ..."
        threadDelay 10000000
        let redeemer= if  forceRedeem
                        then SecpTestSkipRedeemer
                        else SecpTestRedeemerWithSig  (toBuiltin $ serialiseSignature  signedData)
            tx2Builder= walletConstraint
              <>  txRedeemTxin (TxIn txId1 $ TxIx 0)
                      (toTxPlutusScript TestContract.testScriptPlutusV2)
                      (fromPlutusData $ toData redeemer)   (Just $ ExecutionUnits 6000000000 10000000)
       
         -- STEP2: Try redeeming the utxo with signature


        putStrLn $ "Step2: Redeem funds from contract :"
        BS.putStrLn  $ prettyPrintJSON tx2Builder
        txId1<- performSubmission  nodeInfo tx2Builder
        pure ()

      Cat ->    let textEnvelope = serialiseToTextEnvelope Nothing (PlutusScript PlutusScriptV2 $ TestContract.testScriptPlutusV2)
                in  putStrLn $ BS8.unpack (A.encode textEnvelope)
scriptHash = hashScript   $ PlutusScript PlutusScriptV2 $ TestContract.testScriptPlutusV2

scriptAddr = shelleyAddressInEra $ makeShelleyAddress Mainnet (PaymentCredentialByScript scriptHash) NoStakeAddress

genEcdsaSignKey :: IO (SignKeyDSIGN EcdsaSecp256k1DSIGN)
genEcdsaSignKey = do
    seed <- readSeedFromSystemEntropy 32
    pure $ genKeyDSIGN seed

ecdsaSign :: SignKeyDSIGN EcdsaSecp256k1DSIGN -> MessageHash -> SigDSIGN EcdsaSecp256k1DSIGN
ecdsaSign sKey mh = signDSIGN () mh sKey

--Raw verifiction without hashing message first for this raw bench otherwise one should always hash the message first before verification
ecdsaVerify' :: VerKeyDSIGN EcdsaSecp256k1DSIGN -> MessageHash -> SigDSIGN EcdsaSecp256k1DSIGN -> ()
ecdsaVerify' vKey mh sig = let result = verifyDSIGN () vKey mh sig in
    case result of
        Left err -> error "Verification failed."
        Right _ -> ()

secp25k1Verify :: ByteString -> ByteString -> ByteString -> Bool
secp25k1Verify vKey mh sig = verifyEcdsaSecp256k1Signature  (toBuiltin vKey) (toBuiltin  mh) (toBuiltin sig)

serialiseVkey = rawSerialiseVerKeyDSIGN
serialiseSignature = rawSerialiseSigDSIGN
-- serialiseByteString = serialize'  

performSubmission  nodeInfo txBuilder = txBuilderToTxIO nodeInfo txBuilder >>= (\case
           Left fe -> throw fe
           Right tx -> submitTx (getConnectInfo nodeInfo) tx >>= (\case
                Left fe -> throw fe
                Right x0 ->do
                  let txId =  getTxId $ getTxBody tx
                  putStrLn $ "Tx Submitted :" ++ show txId
                  pure txId)
          )