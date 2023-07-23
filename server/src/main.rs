mod prover;
mod slots;

use ethers::{
    prelude::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::LocalWallet,
    types::{Address, Bytes, Eip1559TransactionRequest, U256},
};
use slots::GenerateSlotsResult;
use std::{env, thread};

#[rocket::get("/gen_slots?<address>")]
async fn gen_slots(address: &str) -> String {
    let result = slots::generate(address.parse().unwrap(), None)
        .await
        .unwrap();
    serde_json::to_string(&result).unwrap()
}

// static GLOBAL_PROOF_FLAG: Mutex<bool> = Mutex::new(false);

#[rocket::get("/gen_proof?<address>")]
async fn gen_proof(address: &str) -> String {
    println!("address: {address}");

    //  ethers::signers::LocalWallet
    let wallet = env::var("PROVER_PRIVATE_KEY")
        .unwrap()
        .parse::<LocalWallet>()
        .unwrap();

    let provider = Provider::<Http>::try_from(
        std::env::var("OPTIMISM_RPC_URL").expect("please pass JSON_RPC_URL env var"),
    )
    .unwrap();

    let client = SignerMiddleware::new_with_provider_chain(provider, wallet)
        .await
        .unwrap();

    let tx = Eip1559TransactionRequest::new()
        .to("0xcf7d2b6bffc26497c8f759363d6baeda5074d7f1"
            .parse::<Address>()
            .unwrap())
        .data("0x2ae3594a".parse::<Bytes>().unwrap());

    let pending_tx = client.send_transaction(tx, None).await.unwrap();

    // get the mined tx
    let receipt = pending_tx.await.unwrap().expect("tx dropped from mempool");

    let data = receipt.logs[0].data.to_owned();
    let (bk, _) = data.split_at(32);

    let block_number = U256::from_big_endian(bk).as_u32();
    println!("block_number: {block_number}");

    let GenerateSlotsResult { slots, values: _ } =
        slots::generate(address.parse().unwrap(), Some(block_number))
            .await
            .unwrap();

    let address_parsed: Address = address.parse().unwrap();

    println!("{slots:?}");

    // let block_number = 17748120; // TODO pin block hash on optimism and record the block hash
    let result = thread::spawn(move || {
        println!("start");
        prover::prove(block_number, address_parsed, slots)
    })
    .join()
    .expect("Thread panicked");
    // *global_proof_flag = false;
    result
    // serde_json::to_string(&result).unwrap()
}

#[rocket::launch]
fn rocket() -> _ {
    rocket::build().mount("/", rocket::routes![gen_slots, gen_proof])
}

// #[tokio::main]
// async fn main() {
//     // prover::prove(
//     //     17669947,
//     //     "0x6B175474E89094C44Da98b954EedeAC495271d0F"
//     //         .parse()
//     //         .unwrap(),
//     //     vec![
//     //         "0x6ec2e6c897385970ba04372be8062facf4b86db4389f769313f8c3bb0e04dd31"
//     //             .parse()
//     //             .unwrap(),
//     //     ],
//     // );

//     // println!("first");

//     // let block_number = 17669947; // TODO pin block hash on optimism and record the block hash
//     // let address = "0x6dC501a9911370285B3ECc2830dd481fFCDDa348"
//     //     .parse()
//     //     .unwrap();
//     // let GenerateSlotsResult { slots, values: _ } = slots::generate(address).await.unwrap();
//     // // let res = prover::prove(block_number, address, slots);

//     let result = thread::spawn(move || {
//         let block_number = 17669947; // TODO pin block hash on optimism and record the block hash
//         prover::prove(
//             17748120,
//             "0x6dC501a9911370285B3ECc2830dd481fFCDDa348"
//                 .parse()
//                 .unwrap(),
//             vec![
//                 "0x0000000000000000000000000000000000000000000000000000000000000003"
//                     .parse()
//                     .unwrap(),
//                 "0x0000000000000000000000000000000000000000000000000000000000000004"
//                     .parse()
//                     .unwrap(),
//                 "0xe90b7bceb6e7df5418fb78d8ee546e97c83a08bbccc01a0644d599ccd2a7c2e0"
//                     .parse()
//                     .unwrap(),
//                 "0x6ec2e6c897385970ba04372be8062facf4b86db4389f769313f8c3bb0e04dd31"
//                     .parse()
//                     .unwrap(),
//                 "0x0e6172401a8cb5887a05ed63af6b99f7e24998adb51b0be73e51d2498e76c174"
//                     .parse()
//                     .unwrap(),
//                 // "0x000000000000000000000000000000000000000000000000000000000000dead"
//                 //     .parse()
//                 //     .unwrap(),
//             ],
//         )
//     })
//     .join()
//     .expect("Thread panicked");

//     println!("Hello, world! {:?}", result);
// }
