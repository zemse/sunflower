![Trustless-3 copy](https://github.com/zemse/sunflower/assets/22412996/ae804c27-8be9-4d2b-bf05-203e9d3a5fc8)

# sunflower

this project is a gnosis safe plugin that is used by a multi-sig on L2 to inherit ownership of a multi-sig on L1.

ethglobal submission link: https://ethglobal.com/showcase/sunflower-ogbj9

the optimism L2 has a precompile which gives access to L1's block hash. this allows access to the execution details of L1. however, doing MPT proofs + RLP can be costly in terms of computation and call data size. hence, in this hack, i am using open-source code developed by the axiom team, along with some modifications to provide a zk proof of storage slots given a block hash.

## server

a rocket-rs backend server which accepts REST API requests for the endpoint `/gen_proof?address=<L1-multisig>` that generates proofs given an address of L1 gnosis multi-sig. from the multisig address, the storage slot keys are calculated based on the storage layout of gnosis multisig (which uses a mapping) and then these are used with axiom circuits to generate a proof of its value. 

to run the backend server:

```
cd server

PROVER_PRIVATE_KEY=<key with some optimism eth> DEBUG=true OPTIMISM_RPC_URL=<optimism rpc url>  JSON_RPC_URL=<eth mainnet rpc url> cargo run --release
```

## contracts

this is solidity code that parses the proofs and the plugin business logic. there is a `OptimismBlockCache` contract which is called everytime prover is generating proof to pin the L1 block hash on optimism L2 network so it is accessable when user is verifying the proof. the `SunflowerSafePlugin` uses the plonk verifier generated through axiom circuits to check if the proof is valid and then parses the public instances to get owner list and threshold. following that the ordinary signature verification code from gnosis safe contracts is used. 

to run the test cases:

```
cd contracts

forge test
```

for deploying contracts i've just used `forge flatten <path>` + remix.

## running the frontend

demo UI to interact with the plugin on an optimism L2 multi-sig. frontend depends rust backend for generating a proof. cors checks are required to be disabled in the browser bcz i didn't have time to deal with fixing cors during hackathon.

```
cd frontend

yarn start
```

## license

MIT
