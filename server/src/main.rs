mod slots;
use slots::gen_slots;

#[tokio::main]
async fn main() {
    let res = gen_slots(
        "0x6dC501a9911370285B3ECc2830dd481fFCDDa348"
            .parse()
            .unwrap(),
    )
    .await
    .unwrap();

    println!("Hello, world! {:?}", res);
}
