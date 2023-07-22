mod prover;
mod slots;

use ethers::types::Address;
use slots::GenerateSlotsResult;
use std::{sync::Mutex, thread};

#[rocket::get("/gen_slots?<address>")]
async fn gen_slots(address: &str) -> String {
    let result = slots::generate(address.parse().unwrap()).await.unwrap();
    serde_json::to_string(&result).unwrap()
}

static GLOBAL_PROOF_FLAG: Mutex<bool> = Mutex::new(false);

#[rocket::get("/gen_proof?<address>")]
async fn gen_proof(address: &str) -> String {
    println!("address: {}", address);
    // let mut global_proof_flag = GLOBAL_PROOF_FLAG.lock().unwrap();
    // if *global_proof_flag {
    //     return String::from("in progress already please wait");
    // }
    // *global_proof_flag = true;
    let GenerateSlotsResult { slots, values: _ } =
        slots::generate(address.parse().unwrap()).await.unwrap();

    let address_parsed: Address = address.parse().unwrap();
    // let result = thread::spawn(move || {
    //     let block_number = 17669947;
    //     // TODO pin block hash on optimism and record the block hash
    //     prover::prove(block_number, address_parsed, slots)
    // })
    // .join()
    // .expect("Thread panicked");

    println!("{:?}", slots);

    let block_number = 17748120; // TODO pin block hash on optimism and record the block hash
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
