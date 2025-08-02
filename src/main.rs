#[allow(unused_imports)]
use log::{LevelFilter, debug, error, info, warn};
use rust_http_server::config::Config;
use rust_http_server::tcp_handlers::run_tcp_server;
use std::{env, error::Error};

use std::io::Write;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Err(message) = init_logger() {
        eprintln!("Failed to initialize logger: {}", message);
        return Err(message);
    }

    let args = env::args().collect::<Vec<String>>();
    let config = Config::new(args).await?;

    info!("Starting TCP server with configuration: {config:#?}");

    if let Err(e) = run_tcp_server(config).await {
        error!("Server crash: {}", e);
        return Err(e);
    }

    Ok(())
}

fn init_logger() -> Result<(), Box<dyn Error + Send + Sync>> {
    let target = Box::new(
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("logs/logs.log")
            .inspect_err(|e| eprintln!("Failed to open log file: {}", e))?,
    );
    let target = std::sync::Mutex::new(target);

    // For logging to stderr and file

    env_logger::Builder::new()
        .target(env_logger::Target::Stderr) // Or Target::Stdout
        .filter(None, LevelFilter::Debug)
        .format(move |buf, record| {
            let log_line = format!(
                "[{} {} {}:{}] {}\n",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            );

            {
                let mut file = target.lock().unwrap();
                let _ = file.write_all(log_line.as_bytes());
            }

            buf.write_all(log_line.as_bytes())
        })
        .init();

    // For only logging to file

    // env_logger::Builder::new()
    //     // .target(env_logger::Target::Pipe(target))
    //     .filter(None, log::LevelFilter::Debug)
    //     .format(|buf, record| {
    //         writeln!(
    //             buf,
    //             "[{} {} {}:{}] {}",
    //             chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
    //             record.level(),
    //             record.file().unwrap_or("unknown"),
    //             record.line().unwrap_or(0),
    //             record.args()
    //         )
    //     })
    //     .init();

    Ok(())
}
