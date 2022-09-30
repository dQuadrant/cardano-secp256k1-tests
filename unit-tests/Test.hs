
import qualified Test.EcdsaSecp256k1Tests as EcdsaSecp256k1Tests
import qualified Test.SchnorrSecp256k1Tests as SchnorrSecp256k1Tests
import           Test.Tasty

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Secp-256k1 tests" [
         EcdsaSecp256k1Tests.tests,
         SchnorrSecp256k1Tests.tests
    ]