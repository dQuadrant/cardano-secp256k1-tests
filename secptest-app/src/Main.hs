{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}
module Main
where
import qualified TestContract(testScriptPlutusV2, SecpTestDatum (SecpTestDatum))
import Cardano.Api (serialiseToTextEnvelope, Script (PlutusScript), prettyPrintJSON, NetworkId (Mainnet), getTxId, TxIx (TxIx))
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
                     deriveVerKeyDSIGN, genKeyDSIGN, VerKeyDSIGN),
      EcdsaSecp256k1DSIGN, hashAndPack, fromMessageHash, verifyDSIGN, toMessageHash )
import Cardano.Crypto.Seed (readSeedFromSystemEntropy)
import Data.ByteString.Random (random)
import Cardano.Kuber.Util (toHexString)
import TestContract (testDatumData, SecpTestDatum (testDatumPubKey))
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
import Cardano.Api (TxIn(..), ExecutionUnits (ExecutionUnits))
import Control.Concurrent (threadDelay)
import Data.ByteString (ByteString)
import PlutusTx.Builtins (verifyEd25519Signature)

data Modes =
      Emulate {
        signKeyFile:: String,
        address :: Maybe Text,
        noPreVerify:: Bool
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
            noPreVerify = def &=typ "Pre-Verify"
        }
        ,Cat
        ]

    case op of
      Emulate signkeyFile mAddr noPreVerify -> do
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
        
        if  noPreVerify  || ecdsaVerify (serialiseByteString ecdsaVkey) messageHashBs (serialiseByteString signedData)
          then pure()
          else do
              putStrLn $ "ecdsaVerify " ++ (toHexString $ serialiseByteString ecdsaVkey) ++ " " ++ toHexString  messageHashBs ++ " " ++ toHexString (serialiseByteString signedData)
              fail "Error pre-validating signature using plutus function"
        putStrLn $ "secp256k1 SignKey:" ++ show ecdsaSignKey
        putStrLn $ "messageHash: " ++ toHexString messageHashBs
        let lockedDatum = TestContract.SecpTestDatum {
                testDatumData = toBuiltin  messageHashBs
              , testDatumPubKey = toBuiltin $  serialiseByteString ecdsaVkey
              }
            tx1Builder = walletConstraint <> txPayToScriptWithData scriptAddr  mempty (fromPlutusData $ toData lockedDatum)
        putStrLn $ "Step1: Lock funds to the contract :"
        BS.putStrLn  $ prettyPrintJSON tx1Builder
        txId<- txBuilderToTxIO nodeInfo tx1Builder >>= (\case
           Left fe -> throw fe
           Right tx -> submitTx (getConnectInfo nodeInfo) tx >>= (\case
                Left fe -> throw fe
                Right x0 ->do
                  let txId =  getTxId $ getTxBody tx
                  putStrLn $ "Tx Submitted :" ++ show txId
                  pure txId)
          )
        putStrLn $ "Waiting 10 seconds for transaction confirmation ..."
        threadDelay 10000000
        let redeemer= TextContract.SecpTestRedeemer (toBuiltin $ serialiseByteString  signedData)
            tx2Builder= walletConstraint
              <>  txRedeemTxin (TxIn txId $ TxIx 0)
                      (toTxPlutusScript TestContract.testScriptPlutusV2)
                      (fromPlutusData $ toData redeemer) (Just $ ExecutionUnits 6000000000 10000000)
        putStrLn $ "Step2: Redeem funds from contract :"
        BS.putStrLn  $ prettyPrintJSON tx2Builder
        txId<-txBuilderToTxIO nodeInfo tx2Builder >>= (\case
           Left fe -> putStrLn "txBuildError" >> throw fe
           Right tx -> submitTx (getConnectInfo nodeInfo) tx >>= (\case
                Left fe -> putStrLn "txSubmitError" >> throw fe
                Right x0 ->do
                  let txId =  getTxId $ getTxBody tx
                  putStrLn $ "Tx Submitted :" ++ show txId
                  pure txId)
          )
        pure ()

      Cat ->    let textEnvelope = serialiseToTextEnvelope Nothing (PlutusScript PlutusScriptV2 $ TestContract.testScriptPlutusV2)
                in  putStrLn $ BS8.unpack (A.encode textEnvelope)
scriptAddr = plutusScriptAddr (toTxPlutusScript  TestContract.testScriptPlutusV2) Mainnet


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

ecdsaVerify :: ByteString -> ByteString -> ByteString -> Bool
ecdsaVerify vKey mh sig = verifyEd25519Signature  (toBuiltin vKey) (toBuiltin  mh) (toBuiltin sig)

serialiseByteString  bs=  serialize'  bs
-- serialiseByteString = serialize'  