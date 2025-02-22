/*
    NOTE: That was does purely for educational purposes, I would not recommend using this in production as it's file system based database and reinvented wheel ,.
*/

use crate::config::{config_file::DatabaseConfigEntry, Config};
use crate::prelude::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::marker::PhantomData;
use tokio::sync::MutexGuard;

use std::{
    path::PathBuf,
    sync::{atomic::AtomicU8, Arc},
};
use strum_macros::EnumIter;

use tokio::{
    fs::File,
    io::{AsyncSeekExt, AsyncWriteExt},
};

/// `NOTE`: There could be multiple instances of Database, thought they would point to a different storage of data
///
/// `Schema` Serves its purpose to be able to parse the JSON file in which the database is stored
/// to the type of T using serde_json
#[derive(Debug)]
pub struct Database<T> {
    d_type: DatabaseType,
    handler: Arc<Mutex<File>>,
    _marker: PhantomData<T>,
}

impl<'de, T> Database<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    pub async fn new(config: &MutexGuard<'_, Config>, d_type: DatabaseType) -> Self {
        // let let handle = Database::new(DatabaseType::Users);
        // Database::exec(DatabaseCommand::Insert(database_entry));

        let handler = Self::init(&config, &d_type).await.expect(&format!(
            "Could not initialize the database of type: {:#?}",
            d_type
        ));

        Self {
            d_type,
            handler,
            _marker: PhantomData,
        }
    }

    // Clones the reference Arc type, increasing the reference count
    fn get_file(&self) -> Arc<Mutex<File>> {
        Arc::clone(&self.handler)
    }

    async fn create_path(config: &MutexGuard<'_, Config>, segment: &DatabaseType) -> PathBuf {
        let database_root = &config
            .config_file
            .database
            .as_ref()
            .expect("Database not configured")
            .root;

        let mut path = Config::get_server_public()
            .join(database_root)
            .join(segment.to_string().to_lowercase());
        path.set_extension("json");

        return path;
    }

    async fn init(
        config: &MutexGuard<'_, Config>,
        d_type: &DatabaseType,
    ) -> Result<Arc<Mutex<File>>, Box<dyn Error + Send + Sync>> {
        // NOTE: If custom name functionality  would be implement, then we would need some source that maps the names with enums
        // and for now on we do not have it, NOTE: Config file does not have that information, if we would have added something like
        // names field that keeps the names in array, we would still need some functionality to MAP the filenames in the config
        // to enums of certain type, and that would be something that is done in the runtime

        let path = Self::create_path(config, d_type).await;

        return match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .await
        {
            Ok(mut file) => {
                // NOTE: This check is useless if the file was just created
                if file.metadata().await?.len() == 0 {
                    file.write(b"[]").await?;
                    file.flush().await?;
                }

                Ok(Arc::new(Mutex::new(file)))
            }
            Err(message) => {
                panic!("Could not tell if the database file exist or cannot be opened with message: {message}")
            }
        };
    }

    pub async fn insert(&self, entry: impl AsRef<[u8]> + std::fmt::Debug)
    where
        T: std::fmt::Debug,
    {
        let file = self.get_file();
        let file = file.lock().await;

        // NOTE: That could be done to validate the input
        let s_entry =
            serde_json::from_slice::<T>(entry.as_ref()).expect("Could not parse T brother!");

        let mut file = self.handler.lock().await;

        file.write_all(entry.as_ref())
            .await
            .expect("Could not write to the file");

        dbg!(entry);
    }

    pub fn update(&self, entry: T) {
        todo!()
    }
    pub fn delete(&self, id: u32) {
        todo!()
    }
    pub fn select(&self, id: u32) {
        todo!()
    }
    pub fn select_all(&self) {
        todo!()
    }
}

// NOTE: ACTUALLY this could implement some reliable default functionality as it's very generic
// thought that would involve parsing and shit

// trait DatabaseCommands<T> {
//     fn insert(&self, entry: T);
//     fn update(&self, entry: T);
//     fn delete(&self, id: u32);
//     fn select(&self, id: u32);
//     fn select_all(&self);
// }

/// The DatabaseType describes which database to initialize, it would stay unutilized until constructed
///
/// `NOTE`: Enum naming reflect the file name of the underlying database as lowercase, it will automatically
/// create databases filenames with defined enum variants.
// TODO: Provide opting out of the behavior of automatically creating the database with provided enum names
// and allow to supply it's own database name instead using the one defined as an enum variant
// NOTE: Explore the idea to allow creation of a field named "names" under database field to use those for creation of databases
// You could do DatabaseType::Entry(name) then to associate a Type with a name
// but doing that you would have to keep some kind of container for that data to for example handle cases
// of already occupied names, remember that the name of database is only stored in the Database instance of a certain type
// although we could rely on the filesystem to handle that for us, thought that would be a bit more error prone

#[derive(Debug, EnumIter, Serialize, Deserialize, strum_macros::Display)]
pub enum DatabaseType {
    Users,
    Tasks,
}

/// `NOTE`: Not really fully fledged write-ahead logging
/// log ile will be in a text format, thought entries will be written per line in the JSON format
/// so to avoid parsing the whole file every time we want to write the entry
/// NOTE: I would keep the write-ahead log to be Database agnostic, thought some field identifying
/// correct one should be stored in while writing the command;
///
/// Gets initialized only when the Database is initialized for the first time, is database agnostic, stores the commands in one file
/// that corresponds to every file
#[derive(Debug)]
pub struct DatabaseWAL {
    wal: Arc<Mutex<File>>,
    size: Arc<AtomicU8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DatabaseTask {
    pub value: String,
    pub id: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DatabaseUser {
    pub name: String,
    pub id: u32,
}

impl DatabaseTask {
    // Expects a parsable JSON String
    //
    // Could fail if not valid JSON
    // pub fn new(entry: Option<&Vec<u8>>) -> Result<Self, Box<dyn Error + Send + Sync>> {
    //     let mut error = HttpRequestError {
    //         content_type: Some(String::from("application/json")),
    //         message: Some(String::from("Internal Server Error")),
    //         ..Default::default()
    //     };

    //     let body = entry.ok_or_else(|| {
    //         eprintln!("Request body is empty");

    //         error.message = Some(String::from("Request body is empty"));
    //         error.clone()
    //     })?;

    //     return Ok(serde_json::from_slice::<DatabaseTask>(&body).map_err(|e| {
    //         eprintln!("Error deserializing database entry: {:#?}", e);
    //         error.clone()
    //     })?);
    // }
}

impl DatabaseWAL {
    /// `NOTE`: Exec is only for internal usage
    pub async fn exec<T: Serialize + DeserializeOwned + std::fmt::Debug>(
        &self,
        command: DatabaseCommand<T>,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        match &command {
            DatabaseCommand::Insert(_, _) => {
                let file = self.get_wal();
                let mut file = file.lock().await;

                if self.size.load(std::sync::atomic::Ordering::SeqCst) == 100 {
                    let file_std = file
                        .try_clone()
                        .await
                        .expect("Could not into_std")
                        .into_std()
                        .await;

                    let lines = serde_json::from_reader::<
                        std::io::BufReader<std::fs::File>,
                        Vec<DatabaseCommand<T>>,
                    >(std::io::BufReader::new(file_std))
                    .expect("Could not parse the command-log");

                    let size = Arc::clone(&self.size);

                    // NOTE: That should definitely not be there, as it would require the same chunk of code to be repeated
                    // thread::spawn(move || {
                    //     // TODO: Execute the commands in command-log

                    //     // NOTE: That should be done in a separate function
                    //     for line in lines {
                    //         match line {

                    //             DatabaseCommand::Insert(database_entry) => (),
                    //             DatabaseCommand::Update(database_entry) => (),
                    //             DatabaseCommand::Delete(id) => (),
                    //             DatabaseCommand::Select(id) => (),
                    //             DatabaseCommand::SelectAll => (),
                    //         }
                    //     }

                    //     size.store(0, std::sync::atomic::Ordering::SeqCst);
                    // })
                    // .join()
                    // // NOTE: Handle the error
                    // .expect("Could not join the thread");
                };

                // NOTE: This should happen after the code in the thread

                file.write_all(format!("{command:?}\n").as_bytes()).await?;
                file.flush().await?;
                file.seek(std::io::SeekFrom::Start(0)).await?;

                let prev = self.size.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                println!("Prev: {}", prev);

                Ok(String::new())
            }
            DatabaseCommand::Update(_, _) => todo!(),
            DatabaseCommand::Delete(_) => todo!(),
            DatabaseCommand::Select(_) => todo!(),
            DatabaseCommand::SelectAll => todo!(),
        }
    }

    /// NOTE: This function should be invoked only
    pub async fn new(
        config: &DatabaseConfigEntry,
    ) -> Result<DatabaseWAL, Box<dyn Error + Send + Sync>> {
        // This initializes the actual database file as well as the WAL file
        // maybe we will abstract it away to separate struct later on.

        // Create the logging file for the commands
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .read(true)
            .open(&config.wal)
            .await?;

        Ok(DatabaseWAL {
            wal: Arc::new(Mutex::new(file)),
            size: Arc::new(AtomicU8::new(0)),
        })

        // let database = serde_json::from_slice::<Vec<DatabaseTask>>(&buffer)?;
    }

    pub fn get_wal(&self) -> Arc<Mutex<File>> {
        Arc::clone(&self.wal)
    }
}

// The problem with database is that it has it's tradeoffs with the possible implementations of it that I am seeing;
// The main issue is that it is just a file which posses a lot of tradeoffs:
// 1. Too add a new entry, we have to read the whole file, parse it, add the new entry, serialize it and write it back
// to optimize the process when have 2 solutions that I see:
// 1.1 We could hold a buffer for parsed database at some time, keep it sync with what is in the file which itself posses a risk
// and hold another field with a link to a file open for writing so that we could avoid the sys call to open a file, thought probably
// we would have to put it into the Arc<Mutex<T>>
// 1.2 We could do that in one take when writing an entry, or just storing the reference to file, thought that is not that much of a performance improvement
// All of the above we have been avoided if we would just use SQL.

// The other way of doing that could be to keep something like a temp file that stores the `commands` that should be executed on the database
// thought that file should be session based, otherwise the file could also grow big, assuming we would execute those commands on server
// clean up, actually the better way would be to flush it more often then.
// This seems like a better approach because, we would not have to parse the whole database file every so often, thought for actual
// modifications we would have to parse the whole file, thought that would be done less often then the other way around.
// Maybe for the commands file to now grow to big we could execute those when like 100 commands are in the file,

// We'll build a command system, for now we only need insertion, thought something like Update, Delete, Select would be nice
// Easiest way thought not most performant is JSON file with commands.
// QUESTION: When do we execute the commands
// ANSWER: We are creating a file instead of storing it in memory because we want to persist the commands in case of server crash
// for performance reasons we could store it in memory, but given that the tasks are async, working independently of each other
// that would involve Arc<Mutex<T>>, also executing the commands on certain threshold or on system shutdown must be done on separate thread
// so to avoid blocking the IO overhead, though the IO is async from tokio, thought don't sure if windows supports async IO

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum DatabaseCommand<T>
where
    T: std::fmt::Debug,
{
    Insert(DatabaseType, T),
    Update(DatabaseType, T),
    Delete(u32),
    // Select and SelectAll are commands that cannot be buffered in the WAL file,
    // as they are not trigger the side effect on database, so they will not be stored in the WAL file
    // if executed, but evaluated eagerly
    Select(u32),
    SelectAll,
}

// IO buffered commands executed on the database, on system shutdown or 100 commands in the buffer
// struct DatabaseCommand {
//     // This has to be strictly ordered, we should eliminate the race conditions in which commands are written to the File.
//     command: Command,
//     // NOTE: For now we will rely on Arc::count_strong to determine when to execute the commands
//     // count: AtomicUsize,
//     // File open for writings, NOTE: We are changing the approach for the File to be JSON format, because that would involve parsing that File
//     // every time to want to write it it, and this should be performance and concurrency oriented
//     // file: Arc<Mutex<File>>,
// }

// Root Mutex -> Database
// Commands -> Arc::clone(&root) -> Increase the reference count, allowing use to see the Arc::count_strong and write then Arc::count_strong == 100
// UPDATE: Not true.
