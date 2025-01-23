use rust_http_server::config::Config;
use rust_http_server::tcp_handlers::run_tcp_server;
use std::{env, error::Error};

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().collect::<Vec<String>>();

    let config: Config = Config::parse_args(args)?;
    run_tcp_server(config)?;

    Ok(())
}
