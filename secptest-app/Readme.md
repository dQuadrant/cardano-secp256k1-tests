## Testing secp25k1Verification function on Local Cluster 

### Step1: Install cardano-node and cardano-cli (with secpt256k1 support) [Uninstall, or change precedence of  older one if present]

```bash
git clone origin  https://github.com/input-output-hk/cardano-node.git
cd cardano-node
git fetch origin pull/4481/head:pr-4481
git checkout pr-4481
cabal install cardano-node 
cabal install cardano-cli
```

### Step2: Start localcluster and perform babbage era hardfork.
 #### 2.1 : Start cluster
```
    git clone https://github.com/mlabs-haskell/plutip
    cd ./plutip
    git checkout origin/vasil-local-cluster-cabal-build
    cabal update
    cabal run local-cluster tempdata 
 ``` 

 #### 2.2 [on another terminal] Perform Babbage era hardfork
 ```
    export CARDANO_NODE_SOCKET_PATH="$(readlink -f ./tempdata/node/node.socket)"
    bash './cluster-data/update-proposal-major-version.sh'
    cardano-cli query tip --mainnet ## try this until the cluster transitions to babbage era
    bash './cluster-data/update-proposal-cost-model.sh' #This will block until the babbage era transition occurs.
 ```


# Step3: [while cluster is running] Run secp256k1 test  with plutus contract on  the cluster 

```
    export PLUTUP_ROOT="$(readlink -f /home/user/plutip)" ##!! Replace this with your plutip root
    export CARDANO_NODE_SOCKET_PATH="$PLUTIP_ROOT/tempdata/node/node.socket"
    git clone https://github.com/dQuadrant/cardano-secp256k1-tests
    cd cardano-secp256k1-tests
    cabal update
    NETWORK=mainnet cabal run  -- secptest-app  emulate -s $PLUTIP_ROOT/cluster-data/utxo-keys/utxo1.skey
```
