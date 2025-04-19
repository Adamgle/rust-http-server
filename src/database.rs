#![allow(warnings)]
/*
    NOTE: That was does purely for educational purposes, I would not recommend using this in production as it's file system based database and reinvented wheel (rectangular one).
*/

use crate::config::{config_file::DatabaseConfigEntry, Config};
use crate::{config, prelude::*};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::atomic::AtomicUsize;
use std::thread;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
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

// Type alias for structure of the Database defined as the HashMap (as we need unique identifier) of generic type T
type DatabaseStorage<Schema: serde::Serialize + DeserializeOwned + std::fmt::Debug> =
    HashMap<usize, Schema>;

/// Database with write-ahead log support that is used to persist the data in the file system
/// and flush it the disk when the server is shutting down or when the WAL file reaches 100 commands.
///
/// `NOTE`: There could be multiple instances of Database, thought they would point to a different storage of data
///
/// `T` Serves its purpose to be able to parse the JSON file in which the database is stored
/// to the type of T using serde_json
#[derive(Debug)]
pub struct Database<'a, Schema>
where
    Schema: serde::Serialize + DeserializeOwned + std::fmt::Debug,
{
    /// Write-ahead log file that is used to persist the data in the file system.
    ///
    /// Is Database agnostic, meaning it should holds multiple `DatabaseType` of data.
    wal: DatabaseWAL,
    /// Type of the database, used to determine which database to use when writing the data to the file system.
    d_type: DatabaseType,
    /// File handle to the underlying storage, written when first invoked with Self::.
    handler: Option<Arc<Mutex<File>>>,
    /// Helper to store the reference to get the config file for the database
    _config: &'a DatabaseConfigEntry,
    /// `_marker`: Is of type PhantomData<T> just to hold the generic `T` so can I parse with serde_json
    _marker: PhantomData<Schema>,
}

impl<'de, Schema> Database<'de, Schema>
where
    Schema: serde::Serialize + DeserializeOwned + std::fmt::Debug,
{
    pub async fn new(config: &'de MutexGuard<'_, Config>, d_type: DatabaseType) -> Self {
        // NOTE: `expect` should  not happen as there is a check for config existence in `handle_client`
        let database_config = config
            .config_file
            .database
            .as_ref()
            .expect("Config file not configured");

        let handler = Self::open_database_file(&database_config, &d_type)
            .await
            .expect(&format!(
                "Could not initialize the database of type: {:#?}",
                d_type
            ))
            .into();

        let wal = DatabaseWAL::new(config.config_file.database.as_ref().unwrap())
            .await
            .expect("Could not initialize the database write-ahead log");

        Self {
            wal,
            d_type,
            handler,
            _config: database_config,
            _marker: PhantomData,
        }
    }

    /// Clones the reference Arc type, increasing the reference count
    fn get_database_file(&self) -> Arc<Mutex<File>> {
        if let Some(file) = &self.handler {
            // NOTE: Question, do we want to always clone the file handle, do we have to?
            return Arc::clone(file);
        } else {
            panic!("Database file not initialized, please initialize the database first!");
        }
    }

    /// Constructs path to database using `DatabaseType` enum variant which converts to string
    /// in lowercase fashion.
    ///
    /// Does not confirm the file existence.
    async fn create_path(config: &DatabaseConfigEntry, segment: &DatabaseType) -> PathBuf {
        let database_root = &config.root;

        let mut path = Config::get_server_public()
            .join(database_root)
            .join(segment.to_string().to_lowercase());
        path.set_extension("json");

        return path;
    }

    /// Creates the database file if it does not exist, and returns the file handle to it.
    /// Writes the empty JSON object to the file if it is empty.
    async fn open_database_file(
        config: &DatabaseConfigEntry,
        d_type: &DatabaseType,
    ) -> Result<Arc<Mutex<File>>, Box<dyn Error + Send + Sync>> {
        // NOTE: If custom name functionality would be implement, then we would need some source that maps the names with enums
        // and for now on we do not have it,

        // NOTE: Config file does not have that information, if we would have added something like
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
                    file.write(b"{}").await?;
                    file.flush().await?;
                }

                Ok(Arc::new(Mutex::new(file)))
            }
            Err(message) => {
                panic!("Could not tell if the database file exist or cannot be opened with message: {message}")
            }
        };
    }

    /// `NOTE`: That function is static as it does not operate on the instance information,
    /// `d_type` is derived from the WAL file and differs from the one in the instance.
    async fn parse_database(
        config: &'de DatabaseConfigEntry,
        d_type: DatabaseType,
    ) -> Result<DatabaseStorage<Schema>, Box<dyn Error + Send + Sync>> {
        let file: Arc<Mutex<File>> = Self::open_database_file(config, &d_type).await?;
        let mut file = file.lock().await;

        let mut buffer = Vec::<u8>::new();
        file.read_to_end(&mut buffer).await?;

        let database: DatabaseStorage<Schema> = serde_json::from_slice(&buffer)?;

        Ok(database)
    }

    pub async fn parse_wal(
        &self,
    ) -> Result<Vec<DatabaseCommand<Schema>>, Box<dyn Error + Send + Sync>> {
        let file = self.wal.get_handler();
        let mut file = file.lock().await;
        let mut buffer = Vec::<DatabaseCommand<Schema>>::with_capacity(self.wal.get_size());

        file.seek(std::io::SeekFrom::Start(0)).await?;

        let mut reader = BufReader::new(&mut *file).lines();

        while let Some(line) = reader.next_line().await.inspect_err(|e| {
            eprintln!("Potentially corrupted DatabaseCommand in WAL file with: {e}.")
        })? {
            // NOTE: We could use serde_json::from_str::<DatabaseCommand<'de, T>>(&line) to parse the line to DatabaseCommand
            // but that would require the DatabaseCommand to be static and not generic, so we will just use the serde_json::from_slice
            // and then convert it to DatabaseCommand.

            let command: DatabaseCommand<Schema> = DatabaseCommand::deserialize(&line)?;
            println!("Parsed command: {command:?}");

            buffer.push(command);
        }

        todo!()
    }

    /// Executes the command on the WAL file,
    async fn exec(
        &self,
        command: DatabaseCommand<Schema>,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let wal_size = self.wal.get_size();

        if wal_size == 100 || true {
            // First of all, to work on that condition you have to parse the command-log.txt file to DatabaseCommand
            // then we will retrieve data like DatabaseCommand, DatabaseType, Schema
            // NOTE: Schema is unavailable to us, all we have is raw bytes, and we won't parse it as that would diminish performance
            // UPDATE: Maybe the idea of generic in DatabaseCommand would work.

            // The idea is to parse the Databases file once (as there could me more then one database, one for each DatabaseType)
            // then do the logic via DatabaseCommand's and save it.
            // We should separate those calls to different threads so to not block the IO.

            // `NOTE`: We need to somehow get the information of what DatabaseType we are working on,
            // because we want to parse it once.

            // DatabaseType::Tasks is static and should be changed the moment we will have the parsed data.
            let mut storage: DatabaseStorage<Schema> =
                Self::parse_database(self._config, DatabaseType::Tasks).await?;

            let WAL = self.parse_wal().await?;

            for command in WAL {
                match command {
                    // NOTE: On this point bytes
                    DatabaseCommand::Insert(database_type, DatabaseEntry(bytes)) => {
                        // Self::_insert(&mut storage, entry.unwrap())
                        todo!()
                    }
                    DatabaseCommand::Update(database_type, ent) => todo!(),
                    DatabaseCommand::Delete(database_type, id) => todo!(),
                    DatabaseCommand::Select(database_type, id) => todo!(),
                    DatabaseCommand::SelectAll(database_type) => todo!(),
                    // _marker of PhantomData<T>
                    DatabaseCommand::_marker(T) => unreachable!(),
                    _ => eprintln!("Invalid command of: {command:?}"),
                };
            }
        }

        // Below we will write the actual entry to the WAL file.

        let file = self.wal.get_handler();
        let mut file = file.lock().await;

        let command_json = serde_json::to_string(&command)?;

        file.write_all(format!("{command_json:?}\n").as_bytes())
            .await?;
        file.flush().await?;

        // Should not move the cursor as the commands has to be invoked in the order they were executed
        // file.seek(std::io::SeekFrom::Start(0)).await?;

        Ok(String::new())
    }

    pub async fn insert(
        &self,
        entry: &(impl AsRef<[u8]> + std::fmt::Debug),
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        self.exec(DatabaseCommand::Insert(
            self.d_type.clone(),
            DatabaseEntry::new(entry),
        ))
        .await
    }

    pub async fn update(
        &self,
        entry: &(impl AsRef<[u8]> + std::fmt::Debug),
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        self.exec(DatabaseCommand::Update(
            self.d_type.clone(),
            DatabaseEntry::new(entry),
        ))
        .await
    }

    pub async fn delete(&self, id: u32) -> Result<String, Box<dyn Error + Send + Sync>> {
        self.exec(DatabaseCommand::Delete(self.d_type.clone(), id))
            .await
    }

    pub async fn select(&self, id: u32) -> Result<String, Box<dyn Error + Send + Sync>> {
        self.exec(DatabaseCommand::Select(self.d_type.clone(), id))
            .await
    }

    pub async fn select_all(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
        self.exec(DatabaseCommand::SelectAll(self.d_type.clone()))
            .await
    }

    // Internal function that execute the actual code for inserting the entry to the database
    // Generally the stacktrace looks like this: Database::insert -> Database::exec -> Database::_insert
    // Database::insert for convenience
    // Database::exec for buffering the commands, to determine to buffer or write execute the commands to database.
    // Database::_insert for the actual writing to the file

    fn _insert(storage: &mut DatabaseStorage<Schema>, entry: Schema) {
        todo!()
    }
}

// NOTE: ACTUALLY this could implement some reliable default functionality as it's very generic
// thought that would involve parsing and shit

/// The DatabaseType describes which database to initialize, it would stay unutilized until constructed.
///
/// `NOTE`: Enum naming reflect the file name of the underlying database as lowercase, it will automatically
/// create databases filenames with defined enum variants.
///
/// `TODO`: Provide opting out of the behavior of automatically creating the database with provided enum names
/// and allow to supply it's own database name instead using the one defined as an enum variant
///
/// `NOTE`: Explore the idea to allow creation of a field named "names" under database field to use those for creation of databases
/// You could do DatabaseType::Entry(name) then to associate a Type with a name
/// but doing that you would have to keep some kind of container for that data to for example handle cases
/// of already occupied names, remember that the name of database is only stored in the Database instance of a certain type
/// although we could rely on the filesystem to handle that for us, thought that would be a bit more error prone
#[derive(Debug, EnumIter, serde::Serialize, serde::Deserialize, strum_macros::Display, Clone)]
pub enum DatabaseType {
    Users,
    Tasks,
}

/// Gets initialized only when the Database is initialized for the first time, is database agnostic, stores the commands in one file
/// that corresponds to every file.
///
/// `NOTE`: Not really fully fledged write-ahead logging
/// log will be in a text format, thought entries will be written per line in the JSON format
/// so to avoid parsing the whole file every time we want to write the entry
///
/// `NOTE`: I would keep the write-ahead log to be Database agnostic, thought some field identifying
/// correct one should be stored in while writing the command;
#[derive(Debug)]
///
/// `NOTE`: That could not hold a schema because it is database agnostic, meaning it should holds multiple types of data and parses
/// to the correct type when executing the command
pub struct DatabaseWAL {
    handler: Arc<Mutex<File>>,
    size: Arc<AtomicUsize>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct DatabaseTask {
    pub value: String,
    pub id: u32,
    _marker: PhantomData<DatabaseType>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct DatabaseUser {
    pub name: String,
    pub id: u32,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
/// Wrapper around the database entry given as bytes
///
/// `NOTE`: Could also be a type alias for `&[u8]`. We will keep it as a struct for now, maybe we could add some functionality
/// tied to it. Maybe parsing, If that would hold some PhantomData<T> then we could parse it to the type of T, not store it but do it on the fly
/// but now parsing in implemented in the `parsed_database` on Database instance, so we could just use that.
///
/// `NOTE`: We don't want to clone that data into owned Vec<u8>, so we will have to keep it as a reference to the slice of bytes
/// thought that creates the issue with deserializing that data. We would have to parse those bytes into the type of T while writing to WAL file.
///
/// `UPDATE`: Maybe there is a way to omit cloning bytes to Vec<u8>, by parsing
/// `UPDATE`: I think better way would be to just clone to Vector. Doing it this way would result in serializing/deserializing twice,
/// first the bytes => Schema, then (DatabaseCommand written to WAL file as a String) => DatabaseCommand, that essentially also clones the
/// bytes while serializing to Schema, just to avoid the cloning of bytes to Vec<u8>. This way we could store the owned bytes in the DatabaseCommand,
pub struct DatabaseEntry(Vec<u8>);
// #[serde(skip)]
/// That data comes as is from the caller, when we would write to the file we would have to parse it to the type of T
/// `NOTE`: Maybe that should be Optional as it would no produce anything if we deserialize.
// bytes: &'a [u8],
// entry: Option<Schema>,
// pub struct DatabaseEntry<(Vec<u8>);

impl DatabaseEntry {
    // NOTE: Maybe bytes: &[u8] would be better.
    pub fn new(bytes: &(impl AsRef<[u8]>)) -> Self {
        DatabaseEntry(bytes.as_ref().to_vec())
    }
}

impl DatabaseWAL {
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
            handler: Arc::new(Mutex::new(file)),
            size: Arc::new(AtomicUsize::new(0)),
        })

        // let database = serde_json::from_slice::<Vec<DatabaseTask>>(&buffer)?;
    }

    pub fn get_handler(&self) -> Arc<Mutex<File>> {
        Arc::clone(&self.handler)
    }

    pub fn get_size(&self) -> usize {
        self.size.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn increment_size(&self) {
        self.size.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }   

    // / `NOTE`: Now sure if that should be async as the ordering has to be preserved of the WAL
    // / file and not sure if it would be this way.
    // pub async fn read(&self) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {

    // }
}

// The problem with database is that it has it's tradeoffs with the possible implementations of it that I am seeing;
// The main issue is that it is just a file which posses a lot of tradeoffs:
// 1. To add a new entry, we have to read the whole file, parse it, add the new entry, serialize it and write it back
// to optimize the process when have 2 solutions that I see:
// 1.1 We could hold a buffer for parsed database at some time, keep it sync with what is in the file which itself posses a risk
// and hold another field with a link to a file opened for writing so that we could avoid the sys call to open a file, thought probably
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
// ANSWER: We are creating a file instead of storing it in memory because we want to persist the commands in case of server crash.
// For performance reasons we could store it in memory, but given that the tasks are async, working independently of each other
// that would involve Arc<Mutex<T>>, also executing the commands on certain threshold or on system shutdown must be done on separate thread
// so to avoid blocking the IO overhead, though the IO is async from tokio, thought don't sure if windows supports async IO

#[derive(Debug, serde::Serialize, serde::Deserialize)]
/// IO buffered commands executed on the database, on system shutdown or 100 commands in the buffer (memory or WAL file I think).
///
/// `NOTE`: I think DatabaseType is useless as Database instance already has the `d_type` fields with that, we could use that to write to the WAL
/// file for later parsing, but current implementation may be easier.
///
/// `TODO`: Commands like Select, SelectAll should trigger the `Database::exec` as that would could produce stale data if we wouldn't do that.
///
/// `NOTE`: Schema potentially useless as it's not getting written in the WAL file, so either way we do not how to parse it.
pub enum DatabaseCommand<Schema> {
    /// Insert one entry to given DatabaseType with a new entry
    Insert(DatabaseType, DatabaseEntry),
    /// Update one entry to given DatabaseType with a new entry
    Update(DatabaseType, DatabaseEntry),
    /// Delete one entry to given DatabaseType
    Delete(DatabaseType, u32),
    // Select and SelectAll are commands that cannot be buffered in the WAL file,
    // as they are not trigger the side effect on database, so they will not be stored in the WAL file
    // if executed, but evaluated eagerly
    /// Select one entry to given DatabaseType
    Select(DatabaseType, u32),
    /// Select everything to given DatabaseType
    SelectAll(DatabaseType),
    /// NOTE: That would hold Schema of the database, as we don't want to parse the entry while writing
    /// the entry, as it comes as raw bytes, we will parse it later using that generic type
    _marker(PhantomData<Schema>),
}

impl<'a, Schema: serde::Serialize + DeserializeOwned + std::fmt::Debug> DatabaseCommand<Schema> {
    pub fn deserialize(entry: &(impl AsRef<[u8]>)) -> Result<Schema, serde_json::Error> {
        serde_json::from_slice::<Schema>(entry.as_ref())
    }
}
