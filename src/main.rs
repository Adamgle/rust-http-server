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
