use rust_http_server::config::Config;
use rust_http_server::tcp_handlers::run_tcp_server;
use std::{env, error::Error};

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().collect::<Vec<String>>();
    let config: Config = Config::parse_args(args)?;

    // Clone config for use in the ctrl-c handler

    // match config.logger.get_file_log().try_clone().ok() {
    //     Some(mut file) => {
    //         ctrlc::set_handler(move || {
    //             file.seek(std::io::SeekFrom::Start(0)).unwrap();

    //             if let Err(e) = file.set_len(0) {
    //                 eprintln!("Error truncating file on shutdown: {}", e);
    //             }

    //             std::process::exit(0);
    //         })?;
    //     }
    //     None => todo!(),
    // }

    run_tcp_server(&config)?;

    Ok(())
}
