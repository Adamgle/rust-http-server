use rust_http_server::config::Config;
use rust_http_server::tcp_handlers::run_tcp_server;
use std::{env, error::Error};

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().collect::<Vec<String>>();
    let mut config: Config = Config::parse_args(args)?;

    // ctrlc::set_handler(move || {
    //     // Ok(file) => {
    //     if let Err(e) = Logger::truncate_file_log() {
    //         eprintln!("Failed to truncate log file {}", e);
    //     }

    //     std::process::exit(0);
    // })?;

    run_tcp_server(&mut config)?;

    // Logger::truncate_file_log()?;

    Ok(())
}
