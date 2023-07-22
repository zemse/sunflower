use std::str::FromStr;

use ethers::{
    abi::{self, Address},
    providers::{Http, Middleware, Provider},
    types::{BigEndianHash, H256, U256},
    utils::keccak256,
};

use serde::{Deserialize, Serialize};

const SLOTS_LENGTH: usize = 6;

#[derive(Serialize, Deserialize)]
pub struct GenerateSlotsResult {
    pub slots: Vec<H256>,
    pub values: Vec<U256>,
}

pub async fn generate(addr: Address) -> Result<GenerateSlotsResult, String> {
    let provider = Provider::<Http>::try_from(
        std::env::var("JSON_RPC_URL").expect("please pass JSON_RPC_URL env var"),
    )
    .unwrap();

    // TODO cache the block hash might be needed for the current block before generating slots

    let owners_mapping_slot = H256::from_uint(&U256::from(2));
    let owners_count_slot = H256::from_uint(&U256::from(3));
    let threshold_count_slot = H256::from_uint(&U256::from(4));

    let mut slots = vec![owners_count_slot, threshold_count_slot];
    let mut values = vec![
        provider
            .get_storage_at(addr, slots[0], None) // TODO some block
            .await
            .unwrap()
            .into_uint(),
        provider
            .get_storage_at(addr, slots[1], None) // TODO some block
            .await
            .unwrap()
            .into_uint(),
    ];

    let mut key = U256::from(1);
    loop {
        let slot = hash_two(key, owners_mapping_slot);
        slots.push(slot);

        let value = provider
            .get_storage_at(addr, slot, None) // TODO some block
            .await
            .unwrap()
            .into_uint();
        values.push(value);

        if key == U256::one() && value == U256::zero() {
            return  Err(format!("The address {addr} is probably not a valid gnosis safe since the owners mapping slot at sentinal address should be non-zero"));
        }

        if value == U256::one() {
            break;
        } else {
            key = value;
        }
    }

    let dead = H256::from_str("0x000000000000000000000000000000000000000000000000000000000000dead")
        .unwrap();

    // TODO handle overflow of slots length
    // while slots.len() < SLOTS_LENGTH {
    //     slots.push(dead);
    //     values.push(U256::zero())
    // }

    Ok(GenerateSlotsResult { slots, values })
}

fn hash_two(one: U256, two: H256) -> H256 {
    let bytes = abi::encode(&[abi::Token::Uint(one), abi::Token::Uint(two.into_uint())]);
    H256::from(keccak256(bytes))
}
