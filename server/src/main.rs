mod slots;

#[rocket::get("/gen_slots?<address>")]
async fn gen_slots(address: &str) -> String {
    let result = slots::generate(address.parse().unwrap()).await.unwrap();
    format!("{:?}", result)
}

#[rocket::launch]
fn rocket() -> _ {
    rocket::build().mount("/", rocket::routes![gen_slots])
}

// #[tokio::main]
// async fn main() {
//     let res = slots::generate(
//         "0x6dC501a9911370285B3ECc2830dd481fFCDDa348"
//             .parse()
//             .unwrap(),
//     )
//     .await
//     .unwrap();

//     println!("Hello, world! {:?}", res);
// }
