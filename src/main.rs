use log::{LevelFilter, error, info};
use rust_http_server::config::Config;
use rust_http_server::tcp_handlers::run_tcp_server;
use std::{env, error::Error};

use std::io::{BufReader, Seek, Write};

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
    if let Err(message) = save_previous_logs() {
        eprintln!("Failed to save previous logs: {}", message);
    }

    let target = Box::new(
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open("logs/logs.log")
            .inspect_err(|e| eprintln!("Failed to open log file: {}", e))?,
    );

    let target = std::sync::Mutex::new(target);

    // For logging to stderr and file

    env_logger::Builder::new()
        .target(env_logger::Target::Stderr) // Or Target::Stdout
        .filter(None, LevelFilter::Debug)
        // .filter(None, LevelFilter::Off)
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

    return Ok(());
}

fn save_previous_logs() -> Result<(), Box<dyn Error + Send + Sync>> {
    let logs = std::fs::read_to_string("logs/logs.log")?;

    if logs.is_empty() {
        return Ok(());
    }

    // Saves the logs that are getting truncated from logs.log, if any
    let mut history_logs = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open("logs/history_logs.json")
        .inspect_err(|e| eprintln!("Failed to open history log file: {}", e))?;

    let reader = BufReader::new(&mut history_logs);

    let mut h_logs = serde_json::from_reader::<
        _,
        std::collections::HashMap<String, std::collections::HashMap<String, String>>,
    >(reader)
    .inspect_err(|_| {
        eprintln!("Failed to read history log file");
    })?;

    let now = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S%.3f")
        .to_string();

    let mut entries = std::collections::HashMap::<String, String>::new();

    // [2025-08-11 23:39:05.623 INFO src\main.rs:18]

    let mut lines = logs.lines().enumerate();
    let mut key_label: Option<String> = None;
    let mut entry = String::new();

    loop {
        if let Some((idx, line)) = lines.next() {
            // No label found, continue and push
            let (left, right) = (line.find("["), line.find("]"));

            // Label found, we need to make sure it is valid, and it is not just a parenthesis pair.
            // If this is found we need to question our selves, DO WE WANNA PUSH?
            if let (Some(left), Some(right)) = (left, right) {
                // Exclude the brackets from the label
                let label = line[left + 1..right].trim();
                let mut label = label.split(" ").collect::<Vec<_>>();

                if let (Some(time), Some(level), Some(source)) = (
                    label
                        .get(0..2)
                        .map(|slice| slice.iter().cloned().collect::<String>()),
                    label.get(2).cloned(),
                    label.get_mut(3),
                ) {
                    let time =
                        chrono::NaiveDateTime::parse_from_str(&time, "%Y-%m-%d %H:%M:%S%.3f");

                    if let Ok(_) = time
                        && !level.contains(" ")
                        && source.contains(".rs")
                    {
                        let path = std::path::Path::new(source)
                            .strip_prefix(std::env::current_dir()?)
                            .unwrap_or_else(|_| {
                                eprintln!("Failed to strip prefix from path: {}", source);

                                std::path::Path::new(source)
                            });

                        // With some probability we can say that it is the beginning of the entry log
                        // Do not bother doing it better. We could try to match the level to be of all possible types
                        // but here what we have is mostly sufficient.

                        let path = path.display().to_string();
                        *source = path.as_str();

                        // There we already have full entry built, as long as it is not the first entry,
                        // first entry should not be inserted there and should still be buffering.
                        if let Some(key_label) = key_label
                            && idx > 0
                        {
                            entries.insert(key_label.to_string(), std::mem::take(&mut entry));
                        }

                        entry.push_str(line[right + 1..].trim_start());
                        key_label = Some(label.join(" "));

                        continue;
                    }
                }
            }

            entry.push_str(line);
        } else {
            entries.insert(
                // Technically that could not be None.
                key_label
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| String::from("<unlabeled>")),
                entry,
            );

            break;
        }
    }

    h_logs.insert(now, entries);

    history_logs.set_len(0)?;
    history_logs.seek(std::io::SeekFrom::Start(0))?;

    serde_json::to_writer(&mut history_logs, &h_logs)?;

    return Ok(());
}
