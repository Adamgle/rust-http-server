#![allow(warnings)]
/*
    NOTE: That was does purely for educational purposes, I would not recommend using this in production as it's file system based database and reinvented wheel (rectangular one).
*/

use crate::config::{config_file::DatabaseConfigEntry, Config};
use crate::{config, prelude::*};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{self, HashMap, HashSet};
use std::error::Error;
use std::fmt::Debug;
use std::hash::Hash;
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

trait DatabaseEntryTrait: Send + Sync + Debug {}

// NOTE: That is stupid
// impl DatabaseEntryTrait for Box<dyn DatabaseEntryTrait> {}

#[derive(Debug)]
/// `NOTE`: Currently there is an issue regarding the generic in that struct as they should not exist in the first place
/// we will consider dynamic dispatch + trait objects to make it work.
pub struct Database {
    collections: HashMap<DatabaseType, Arc<Mutex<DatabaseCollection>>>,
    WAL: Arc<Mutex<DatabaseWAL>>,
}

impl Database {
    pub(in crate::config) async fn new(
        config: &DatabaseConfigEntry,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            collections: HashMap::new(),
            WAL: Arc::new(Mutex::new(DatabaseWAL::new(&config).await.inspect_err(
                |_| eprintln!("DatabaseWAL could not be initialized."),
            )?)),
        })
    }

    /// `NOTE`: That would not work if we don't have mapping between DatabaseType and generic Schema resolving to the actual type eg. DatabaseTask.
    pub async fn parse_collections(
        collections: &HashSet<DatabaseType>,
    ) -> HashMap<DatabaseType, Box<dyn DatabaseEntryTrait>> {
        unimplemented!()
    }

    pub fn get_collection(&self, d_type: &DatabaseType) -> Option<Arc<Mutex<DatabaseCollection>>> {
        self.collections.get(&d_type).map(|c| Arc::clone(c))
    }

    pub fn get_wal(&self) -> Arc<Mutex<DatabaseWAL>> {
        Arc::clone(&self.WAL)
    }

    fn insert_collection(
        &mut self,
        d_type: DatabaseType,
        collection: Arc<Mutex<DatabaseCollection>>,
    ) {
        self.collections.insert(d_type, collection);
    }
}

// Type alias for structure of the Database defined as the HashMap (as we need unique identifier) of generic type T
type DatabaseStorage = HashMap<usize, Box<dyn DatabaseEntryTrait>>;

/// Database with write-ahead log support that is used to persist the data in the file system
/// and flush it the disk when the server is shutting down or when the WAL file reaches 100 commands.
///
/// `NOTE`: There could be multiple instances of Database, thought they would point to a different storage of data
///
/// `T` Serves its purpose to be able to parse the JSON file in which the database is stored
/// to the type of T using serde_json
#[derive(Debug, Clone)]
pub struct DatabaseCollection {
    /// Mutable reference around Write-ahead log file that is used to persist the data in the file system.
    ///
    /// Is Database agnostic, meaning it should holds multiple `DatabaseType` of data.
    WAL: Arc<Mutex<DatabaseWAL>>,
    /// Type of the database, used to determine which database to use when writing the data to the file system.
    d_type: DatabaseType,
    /// File handle to the underlying storage, written when first invoked with Self::.
    handler: Option<Arc<Mutex<File>>>,
}

impl DatabaseCollection {
    pub async fn new(
        config: &MutexGuard<'_, Config>,
        d_type: DatabaseType,
    ) -> Result<Arc<Mutex<Self>>, Box<dyn Error + Send + Sync>> {
        let database = config.get_database()?;
        let mut database = database.lock().await;

        if let Some(collection) = database.get_collection(&d_type) {
            return Ok(collection);
        }

        let collection = Arc::new(Mutex::new(Self {
            WAL: database.get_wal(),
            handler: Some(Self::open_database_file(config, &d_type).await?),
            d_type: d_type.clone(),
            // _marker: PhantomData,
        }));

        let c = Arc::clone(&collection);
        database.insert_collection(d_type, collection);

        Ok(c)
    }

    /// Clones the reference Arc type, increasing the reference count
    async fn get_handler(
        &self,
        config: &MutexGuard<'_, Config>,
    ) -> Result<Arc<Mutex<File>>, Box<dyn Error + Send + Sync>> {
        if let Some(file) = &self.handler {
            // NOTE: Question, do we want to always clone the file handle, do we have to?
            return Ok(Arc::clone(file));
        }

        Self::open_database_file(config, &self.d_type).await
    }

    pub fn get_wal(&self) -> Arc<Mutex<DatabaseWAL>> {
        Arc::clone(&self.WAL)
    }

    pub fn get_d_type(&self) -> DatabaseType {
        self.d_type.clone()
    }

    /// Constructs path to database using `DatabaseType` enum variant which converts to string
    /// in lowercase fashion.
    ///
    /// Does not confirm the file existence.
    async fn create_path(config: &MutexGuard<'_, Config>, segment: &DatabaseType) -> PathBuf {
        // Safe to unwrap based on previous check in the Config::new
        let database_root = &config.get_database_config().unwrap().root;

        let mut path = Config::get_server_public()
            .join(database_root)
            .join(segment.to_string().to_lowercase());
        path.set_extension("json");

        return path;
    }

    /// Creates the database file if it does not exist, and returns the file handle to it.
    /// Writes the empty JSON object to the file if it is empty.
    async fn open_database_file(
        config: &MutexGuard<'_, Config>,
        d_type: &DatabaseType,
    ) -> Result<Arc<Mutex<File>>, Box<dyn Error + Send + Sync>> {
        // NOTE: If custom name functionality would be implemented, then we would need some source that maps the names with enums
        // and for now on we do not have it,

        // NOTE: Config file does not have that information, if we would have added something like
        // names field that keeps the names in array, we would still need some functionality to MAP the filenames in the config
        // to enums of certain type, and that would be something that is done in the runtime

        let path = Self::create_path(config, d_type).await;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .await?;

        // NOTE: This check is useless if the file was just created
        if file.metadata().await?.len() == 0 {
            file.write(b"{}").await?;
            file.flush().await?;
        }

        Ok(Arc::new(Mutex::new(file)))
    }

    async fn parse_collection(&self) -> Result<DatabaseStorage, Box<dyn Error + Send + Sync>> {
        unimplemented!()
    }

    /// Executes the command on the WAL file,
    async fn exec(&self, command: DatabaseCommand) -> Result<String, Box<dyn Error + Send + Sync>> {
        todo!("exec should be moved to Database as it is not DatabaseCollection specific.");

        let WAL = self.get_wal();
        let mut WAL = WAL.lock().await;

        let wal_size = WAL.get_size();

        if wal_size == 100 {
            let mut storage: HashMap<DatabaseType, DatabaseStorage> = unimplemented!();
            let WAL = WAL.parse_wal().await?;

            for command in WAL {
                match command {
                    DatabaseCommand::Insert(database_type, entry) => {
                        let entry = entry.parse(database_type);
                    }
                    DatabaseCommand::Update(database_type, entry) => {
                        let entry = entry.parse(database_type);
                    }
                    DatabaseCommand::Delete(database_type, id) => todo!(),
                    DatabaseCommand::Select(database_type, id) => todo!(),
                    DatabaseCommand::SelectAll(database_type) => todo!(),
                };
            }

            return Ok(String::new());
        }

        // Below we will write the actual entry to the WAL file.

        let file = WAL.get_handler();
        let mut file = file.lock().await;

        let mut command_json = serde_json::to_string(&command)?;
        command_json.push_str("\r\n");

        let command_json = command_json.as_bytes();

        file.write_all(command_json).await?;
        file.flush().await?;

        WAL.add_collection(command.get_database_type().clone());
        WAL.increment_size();

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

    // fn _insert(storage: &mut DatabaseStorage<Schema>, entry: Schema) {
    // todo!()
    // }
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
#[derive(
    Debug,
    EnumIter,
    serde::Serialize,
    serde::Deserialize,
    strum_macros::Display,
    Clone,
    Eq,
    PartialEq,
    Hash,
)]
pub enum DatabaseType {
    Users,
    Tasks,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct DatabaseTask {
    pub value: String,
    pub id: u32,
}

impl DatabaseEntryTrait for DatabaseTask {}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct DatabaseUser {
    pub name: String,
    pub id: u32,
}

impl DatabaseEntryTrait for DatabaseUser {}

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

impl DatabaseEntry {
    // NOTE: Maybe bytes: &[u8] would be better.
    pub fn new(bytes: &(impl AsRef<[u8]>)) -> Self {
        DatabaseEntry(bytes.as_ref().to_vec())
    }

    /// Parses the entry to the statically typed Schema
    ///
    /// NOTE: This function is STATIC and would require change in definition if new DatabaseType would be added.
    pub fn parse(
        &self,
        d_type: DatabaseType,
    ) -> Result<Box<dyn DatabaseEntryTrait>, Box<dyn Error + Send + Sync>> {
        Ok(match d_type {
            DatabaseType::Users => Box::new(serde_json::from_slice::<DatabaseUser>(&self.0)?),
            DatabaseType::Tasks => Box::new(serde_json::from_slice::<DatabaseTask>(&self.0)?),
        })
    }
}

/// Stores the write-ahead log file for each `DatabaseType`, is `DatabaseType` agnostic.
/// Currently initialization is done in the `Config` constructor, and stored there for the duration of the program.
/// May me moved in the future to something that also abstracts the `DatabaseType`s to something like a wrapper
/// around the `Database` and `DatabaseWAL` to keep the collections initialized there.
///
/// `NOTE`: Not really fully fledged write-ahead logging
/// log will be in a text format, thought entries will be written per line in the JSON format
/// so to avoid parsing the whole file every time we want to write the entry
///
#[derive(Debug)]
/// `NOTE`: That could not hold a schema because it is database agnostic, meaning it should holds multiple types of data and parses
/// to the correct type when executing the command
pub struct DatabaseWAL {
    handler: Arc<Mutex<File>>,
    size: Arc<AtomicUsize>,
    /// Used to keep track of the collections is the WAL file for parsing to avoid later iteration.
    _collections: HashSet<DatabaseType>,
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
            .open(&config.WAL)
            .await?;

        Ok(DatabaseWAL {
            handler: Arc::new(Mutex::new(file)),
            size: Arc::new(AtomicUsize::new(0)),
            _collections: HashSet::new(),
        })
    }

    /// `NOTE`: That would not work unless we know which WAL entry deserializes to what type of Schema.
    /// We need mapping between DatabaseType and Schema.
    ///
    /// Maybe we could parse the entry to
    pub async fn parse_wal(&self) -> Result<Vec<DatabaseCommand>, Box<dyn Error + Send + Sync>> {
        // NOTE: We could use serde_json::from_str::<DatabaseCommand<'de, T>>(&line) to parse the line to DatabaseCommand
        let mut file = self.handler.lock().await;
        let mut buffer = Vec::<DatabaseCommand>::with_capacity(self.get_size());
        file.seek(std::io::SeekFrom::Start(0)).await?;

        let mut reader = BufReader::new(&mut *file).lines();

        while let Some(line) = reader.next_line().await.inspect_err(|e| {
            eprintln!("Potentially corrupted DatabaseCommand in WAL file with: {e}.")
        })? {
            let command: DatabaseCommand = DatabaseCommand::deserialize(&line)?;

            buffer.push(command);
        }

        Ok(buffer)
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

    fn add_collection(&mut self, collection: DatabaseType) {
        self._collections.insert(collection);
    }

    fn get_collections(&self) -> &HashSet<DatabaseType> {
        &self._collections
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
pub enum DatabaseCommand {
    /// Insert one entry to given DatabaseType with a new entry
    Insert(DatabaseType, DatabaseEntry),
    /// Update one entry to given DatabaseType with a new entry
    Update(DatabaseType, DatabaseEntry),
    /// Delete one entry to given DatabaseType
    Delete(DatabaseType, u32),
    // Select and SelectAll are commands that cannot be buffered in the WAL file,
    // as they are not trigger the side effect on database, so they will not be stored in the WAL file
    // if executed, but evaluated eagerly and they will also trigger the execution of the buffered commands as if not, the result could be stale.
    /// Select one entry to given DatabaseType
    Select(DatabaseType, u32),
    /// Select everything to given DatabaseType
    SelectAll(DatabaseType),
    // NOTE: That would hold Schema of the database, as we don't want to parse the entry while writing
    // the entry, as it comes as raw bytes, we will parse it later using that generic type
    //
    // `UPDATE`: There is not access to the Schema type as it is not getting written to the WAL file,
    // we could make that explicit but we won't (actually not sure we can write a type to file).
    // _marker(PhantomData<Schema>),
}

impl DatabaseCommand {
    pub fn get_database_type(&self) -> &DatabaseType {
        use DatabaseCommand::*;
        match self {
            Insert(dt, _) | Update(dt, _) | Delete(dt, _) | Select(dt, _) | SelectAll(dt) => dt,
            _ => unreachable!(),
        }
    }

    pub fn deserialize(entry: &(impl AsRef<[u8]>)) -> Result<Self, serde_json::Error> {
        println!("Deserializing entry: {:?}", entry.as_ref());

        serde_json::from_slice::<Self>(entry.as_ref())
            .inspect_err(|e| eprintln!("Failed to deserialize DatabaseCommand: {e}"))
    }
}
