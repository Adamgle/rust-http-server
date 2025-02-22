// use std::error::Error;
// use std::fs::File;
// use std::fs::OpenOptions;
// use std::io::BufWriter;
// use std::io::Write;

// /// <T: Debugger> = "I don't like my <T>Logger, I don't understand my <T>Logger", SASSY pop culture reference

#[derive(Debug, Clone)]
pub struct Logger {}

// impl Logger {
//     pub fn new() -> Result<Self, std::io::Error> {
//         // We will open for appending, and truncate whenever drop is called or on server shutdown with ctrl-c, using ctrlc crate

//         let file_log = BufWriter::new(
//             OpenOptions::new()
//                 .append(true)
//                 .create(true)
//                 .open("logs/log.txt")?,
//         );

//         // println!("Logger buffer: {}", file_log.metadata()?.len());

//         Ok(Self { file_log })
//     }

//     // pub fn create_shared_logger() -> Arc<Mutex<Logger>> {
//     //     let logger = Logger::new().expect("Failed to create logger");
//     //     Arc::new(Mutex::new(logger))
//     // }

//     // pub fn get_cloned(&self) -> Result<File, std::io::Error> {
//     //     self.file_log.try_clone()
//     // }

//     // pub fn get_file_log(&mut self) -> &mut File {
//     //     &mut self.file_log
//     // }

//     /// Takes file log from get_file_log on the Logger struct
//     /// it is not an method of the instance, to avoid Cloning struct while
//     /// This is a temporary solution, and nothing is more permanent than a temporary solution
//     ///
//     /// After many hours wasted, I conclude that the best solution would to just OPEN ANOTHER FILE WITH DIFFERENT PERMISSION
//     /// then previous one will get dropped and truncated, just like the one opened there
//     /// Of course it could be considered unnecessary system call.
//     pub fn truncate_file_log() -> Result<(), std::io::Error> {
//         // The file log is not opened for truncation, not even for writing
//         // I am not sure if that would work, earlier on it was throwing an error

//         let mut file = OpenOptions::new()
//             .write(true)
//             .truncate(true)
//             .open("logs/log.txt")?;

//         file.flush()?;
//         Ok(())
//     }

//     pub fn log_tcp_stream<T: std::fmt::Display>(
//         &mut self,
//         stream: T,
//     ) -> Result<(), Box<dyn Error + Send + Sync> {
//         let mut data = stream.to_string();
//         data.push_str("\r\n\r\n");

//         self.file_log.write_all(data.as_bytes())?;
//         self.file_log.flush()?;

//         Ok(())
//     }
// }

// // impl Drop for Logger {
// //     fn drop(&mut self) {
// //         // NOTE: We should make sure that the file is truncated even thought it panicked
// //         // maybe while instantiating the Logger -> <DIDO>

// //         if let Err(e) = Self::truncate_file_log() {
// //             // We are not panicking, because that could interrupt the server
// //             // and I don't find this process critical to panic

// //             eprintln!("Error truncating the log file: {}", e);
// //         }
// //     }
// // }
