use std::path::PathBuf;

use axiom_eth::{
    storage::helpers::{StorageScheduler, StorageTask},
    util::scheduler::{evm_wrapper::Wrapper::ForEvm, Scheduler},
    Network,
};
use ethers::types::{Address, H256};

// this needs JSON_RPC_URL env var to be set
pub fn prove(block_number: u32, address: Address, slots: Vec<H256>) -> String {
    let scheduler = StorageScheduler::new(
        Network::Mainnet,
        false,
        false,
        PathBuf::from("configs"),
        PathBuf::from("data"),
    );
    let task = StorageTask::new(block_number, address, slots, Network::Mainnet);

    scheduler.get_calldata(ForEvm(task), true)
}
