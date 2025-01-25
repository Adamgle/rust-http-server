use std::error::Error;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{Seek, Write};

#[derive(Debug)]
pub struct Logger {
    file_log: File,
}

impl Logger {
    pub fn new() -> Result<Self, std::io::Error> {
        // We will open for appending, and truncate whenever drop is called or on server shutdown with ctrl-c, using ctrlc crate
        let file_log = OpenOptions::new()
            .append(true)
            .create(true)
            .open("logs/log.txt")?;

        Ok(Self { file_log })
    }

    pub fn get_file_log(&mut self) -> &mut File {
        &mut self.file_log
    }

    pub fn truncate_file_log(&mut self) -> Result<(), std::io::Error> {
        self.get_file_log().seek(std::io::SeekFrom::Start(0))?;
        self.file_log.set_len(0)
    }

    pub fn log_tcp_stream<T: std::fmt::Display>(
        &mut self,
        stream: T,
    ) -> Result<(), Box<dyn Error>> {
        self.file_log
            .write_all(stream.to_string().trim().as_bytes())?;
        self.file_log.write_all("\r\n\r\n".as_bytes())?;
        self.file_log.flush()?;

        Ok(())
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        // NOTE: We should make sure that the file is truncated even thought it panicked
        // maybe while instantiating the Logger -> <DIDO>

        if let Err(e) = self.truncate_file_log() {
            // We are not panicking, because that could interrupt the server
            // and I don't find this process critical to panic

            eprintln!("Error truncating the log file: {}", e);
        }
    }
}
