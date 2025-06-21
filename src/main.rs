use rust_http_server::config::Config;
use rust_http_server::tcp_handlers::run_tcp_server;
use std::{env, error::Error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = env::args().collect::<Vec<String>>();
    let config = Config::new(args).await?;

    if let Err(e) = run_tcp_server(config).await {
        eprintln!("Server crash: {}", e);
        return Err(e);
    }

    Ok(())
}