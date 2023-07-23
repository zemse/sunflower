# sunflower

This project is a Gnosis Safe plugin that is used by a multi-sig on L2 to inherit ownership of a multi-sig on L1.

The Optimism L2 has a precompile which gives access to L1's block hash. This allows access to the execution details of L1. However, doing MPT proofs + RLP can be costly in terms of computation and call data size. Hence, in this hack, I am using open-source code developed by the Axiom team, along with some modifications to provide a zk proof of storage slots given a block hash.