use ethers::{
    abi::{self, Address},
    providers::{Http, Middleware, Provider},
    types::{BigEndianHash, H256, U256},
    utils::keccak256,
};

fn hash_two(one: U256, two: U256) -> H256 {
    let bytes = abi::encode(&[abi::Token::Uint(one), abi::Token::Uint(two)]);
    H256::from(keccak256(bytes))
}

pub async fn generate(addr: Address) -> Result<(Vec<U256>, Vec<U256>), String> {
    let provider =
        Provider::<Http>::try_from(std::env::var("RPC_URL").expect("please pass RPC_URL env var"))
            .unwrap();

    // TODO cache the block hash might be needed for the current block before generating slots

    let owners_mapping_slot = U256::from(2);
    let owners_count_slot = U256::from(3);
    let threshold_count_slot = U256::from(4);

    let mut slots = vec![owners_count_slot, threshold_count_slot];
    let mut values = vec![
        provider
            .get_storage_at(addr, H256::from_uint(&slots[0]), None) // TODO some block
            .await
            .unwrap()
            .into_uint(),
        provider
            .get_storage_at(addr, H256::from_uint(&slots[1]), None) // TODO some block
            .await
            .unwrap()
            .into_uint(),
    ];

    let mut key = U256::from(1);
    loop {
        let slot = hash_two(key, owners_mapping_slot);
        slots.push(slot.into_uint());

        let value = provider
            .get_storage_at(addr, slot, None) // TODO some block
            .await
            .unwrap()
            .into_uint();
        values.push(value);

        if key == U256::one() && value == U256::zero() {
            return  Err(format!("The address {} is probably not a valid gnosis safe since the owners mapping slot at sentinal address should be non-zero", addr));
        }

        if value == U256::one() {
            break;
        } else {
            key = value;
        }
    }

    Ok((slots, values))
}
