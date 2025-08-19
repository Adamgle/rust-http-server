mod logger;

use log::{error, info};
use rust_http_server::config::Config;
use std::{env, error::Error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Err(message) = logger::init_logger() {
        eprintln!("Failed to initialize logger: {}", message);
        return Err(message);
    }

    let args = env::args().collect::<Vec<String>>();
    let config = Config::new(args).await?;

    info!("Starting TCP server with configuration: {config:#?}");

    if let Err(e) = rust_http_server::run_tcp_server(config).await {
        error!("Server crash: {}", e);
        return Err(e);
    }

    Ok(())
}

// async fn test() {
//     use futures_util::{StreamExt, stream};

//     #[tokio::main]
//     async fn main() {
//         let client = reqwest::ClientBuilder::new()
//             .http2_adaptive_window(true)
//             .build()
//             .unwrap();

//         stream::iter(0..1_000_000)
//             .for_each_concurrent(10, |url| callback(&client, url))
//             .await;
//     }

//     async fn callback(client: &reqwest::Client, url: u64) {
//         let url = format!("http://127.0.0.1:8888/{}", url);

//         let Ok(res) = client.get(url).send().await else {
//             return;
//         };
//         let Ok(text) = res.text().await else { return };
//     }
// }
