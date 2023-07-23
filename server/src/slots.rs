use std::str::FromStr;

use ethers::{
    abi::{self, Address},
    providers::{Http, Middleware, Provider},
    types::{BigEndianHash, BlockId, BlockNumber, H256, U256, U64},
    utils::keccak256,
};

use serde::{Deserialize, Serialize};

const SLOTS_LENGTH: usize = 10;

#[derive(Serialize, Deserialize)]
pub struct GenerateSlotsResult {
    pub slots: Vec<H256>,
    pub values: Vec<U256>,
}

pub async fn generate(
    addr: Address,
    block_number: Option<u32>,
) -> Result<GenerateSlotsResult, String> {
    let block_id = if block_number.is_some() {
        BlockId::Number(BlockNumber::Number(U64::from(block_number.unwrap())))
    } else {
        BlockId::Number(BlockNumber::Latest)
    };

    let provider = Provider::<Http>::try_from(
        std::env::var("JSON_RPC_URL").expect("please pass JSON_RPC_URL env var"),
    )
    .unwrap();

    let owners_mapping_slot = H256::from_uint(&U256::from(2));
    let owners_count_slot = H256::from_uint(&U256::from(3));
    let threshold_count_slot = H256::from_uint(&U256::from(4));

    let mut slots = vec![owners_count_slot, threshold_count_slot];
    let mut values = vec![
        provider
            .get_storage_at(addr, slots[0], Some(block_id))
            .await
            .unwrap()
            .into_uint(),
        provider
            .get_storage_at(addr, slots[1], Some(block_id))
            .await
            .unwrap()
            .into_uint(),
    ];

    let mut key = U256::from(1);
    loop {
        let slot = hash_two(key, owners_mapping_slot);
        slots.push(slot);

        let value = provider
            .get_storage_at(addr, slot, Some(block_id))
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

    let u256_singleton = U256::from_str("0xd9db270c1b5e3bd161e8c8503c55ceabee709552").unwrap();

    // TODO handle overflow of slots length
    while slots.len() < SLOTS_LENGTH {
        slots.push(H256::zero());
        values.push(u256_singleton)
    }

    Ok(GenerateSlotsResult { slots, values })
}

fn hash_two(one: U256, two: H256) -> H256 {
    let bytes = abi::encode(&[abi::Token::Uint(one), abi::Token::Uint(two.into_uint())]);
    H256::from(keccak256(bytes))
}
