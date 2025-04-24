use rust_http_server::config::Config;
use rust_http_server::tcp_handlers::run_tcp_server;
use std::{env, error::Error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // use erased_serde::Deserializer;
    // use std::collections::BTreeMap as Map;

    // static JSON: &'static [u8] = br#"{"A": 65, "B": 66}"#;
    // static CBOR: &'static [u8] = &[162, 97, 65, 24, 65, 97, 66, 24, 66];

    // // Construct some deserializers.
    // let json = &mut serde_json::Deserializer::from_slice(JSON);
    // // let cbor = &mut serde_cbor::Deserializer::from_slice(CBOR);

    // // The values in this map are boxed trait objects, which is not possible
    // // with the normal serde::Deserializer because of object safety.
    // let mut formats: Map<&str, Box<dyn Deserializer>> = Map::new();
    // formats.insert("json", Box::new(<dyn Deserializer>::erase(json)));
    // // formats.insert("cbor", Box::new(<dyn Deserializer>::erase(cbor)));

    // // Pick a Deserializer out of the formats map.
    // let format = formats.get_mut("json").unwrap();

    // let data: Map<String, usize> = erased_serde::deserialize(format).unwrap();

    // println!("{}", data["A"] + data["B"]);

    let args = env::args().collect::<Vec<String>>();
    let config = Config::new(args).await?;

    // ctrlc::set_handler(move || {
    //     // Ok(file) => {
    //     if let Err(e) = Logger::truncate_file_log() {
    //         eprintln!("Failed to truncate log file {}", e);
    //     }

    //     std::process::exit(0);
    // })?;

    if let Err(e) = run_tcp_server(config).await {
        eprintln!("Server crash: {}", e);
        return Err(e);
    }

    Ok(())
}
