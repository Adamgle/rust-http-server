/*
    ### What started as a joke, remained one ###
    NOTE: That was does purely for educational purposes, I would not recommend using this in production as it's a file system based database and reinvented wheel (rectangular one).
*/
#![allow(non_snake_case)]

// ### NOTES ###
// This database is deeply flawed, as insertions are not done in O(1) append only time, since we have to parse the file to
// add a new entry. Implementing the WAL file, which is append only, we could postpone that process, but that is not even the
// biggest issue that is resolved, we still have to bring the data to memory, parse it and operate on it to insert new entries. That also
// means that if we would want to select and entry we would have to flush the WAL file to the database file to provide stateful output.
// It is easy to see that when database grows, the performance of the database would degrade.
// #############

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

pub mod collections;

pub use crate::config::database::collections::{
    DatabaseEntry, DatabaseEntryTrait, DatabaseTask, DatabaseUser,
};

use crate::config::{config_file::DatabaseConfigEntry, Config};
use crate::prelude::*;
use erased_serde::Deserializer;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::atomic::AtomicUsize;
use std::{path::PathBuf, sync::Arc};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::{
    fs::File,
    io::{AsyncSeekExt, AsyncWriteExt},
};

// bounds on generic parameters in type aliases are not enforced
// this is a known limitation of the type checker that may be lifted in a future edition.
// see issue #112792 <https://github.com/rust-lang/rust/issues/112792> for more information
// `#[warn(type_alias_bounds)]` on by default
// T: DatabaseEntryTrait => T
/// We are using Strings as the keys to store uuids.
type DatabaseStorage<T> = HashMap<String, T>;

#[derive(Debug)]
/// `THESIS`: The only interface that we will expose to the user is the `Database` struct impl's with `inherited` public interface on it's fields.
pub struct Database {
    collections: HashMap<DatabaseType, Arc<Mutex<DatabaseCollection>>>,
    WAL: Arc<Mutex<DatabaseWAL>>,
    _database_config_entry: DatabaseConfigEntry,
}

impl Database {
    pub(in crate::config) async fn new(
        config: &DatabaseConfigEntry,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        if let Some(state) = DatabaseWAL::load_state(config).await? {
            // Flush the unprocessed operations on the database that was cached on WAL file.
            let mut instance = Self {
                WAL: state,
                collections: HashMap::new(),
                _database_config_entry: config.clone(),
            };

            // Bad in that context as you can see the state is also in the instance, but it technically makes
            // sens to pass the WAL instance to that method even if it is not clear at this moment, thought maybe I am wrong.

            let WAL = instance.get_wal();
            let WAL = WAL.lock().await;

            instance.execute_commands(WAL).await?;
        }

        return Ok(Self {
            WAL: DatabaseWAL::new(&config)
                .await
                .inspect_err(|_| eprintln!("DatabaseWAL could not be initialized."))?,
            collections: HashMap::new(),
            // I do not mind cloning as those are just 2 PathBuf's.
            _database_config_entry: config.clone(),
        });
    }

    /// Parses the collections occurring in the WAL file to the `HashMap<DatabaseType, DatabaseStorage<Box<dyn DatabaseEntryTrait>>>` type.
    async fn parse_WAL_collections(
        &mut self,
    ) -> Result<
        HashMap<DatabaseType, DatabaseStorage<Box<dyn DatabaseEntryTrait>>>,
        Box<dyn Error + Send + Sync>,
    > {
        let mut storage = HashMap::new();

        let WAL = self.get_wal();
        let WAL = WAL.lock().await;

        let d_types = WAL.get_d_types();

        let config = self._database_config_entry.clone();

        for d_type in d_types {
            // NOTE: DatabaseCollection is actually initialized right there, if it was not previous initialized,
            // otherwise it would be just looked up.
            let collection = self.get_create_collection(&config, d_type.clone()).await?;

            let collection = collection.lock().await;
            let collection = collection.parse_collection().await?;

            storage.insert(d_type.clone(), collection);
        }

        Ok(storage)
    }

    /// Deserializes the WAL file to the `Vec` of raw commands, just as they were written. Takes file handler to WAL file and `size` of WAL file defined on instance.
    ///
    /// `NOTE`: Is defined as a static method to work both in `execute_commands` and `DatabaseWAL::load_state`
    async fn parse_WAL(
        handler: Arc<Mutex<File>>,
        size: usize,
    ) -> Result<Vec<DatabaseCommand>, Box<dyn Error + Send + Sync>> {
        let mut handler = handler.lock().await;

        // let file = WAL.get_handler();
        // let mut file = file.lock().await;

        // let mut file = handler.lock().await;
        let mut buffer = Vec::<DatabaseCommand>::with_capacity(size);

        handler.seek(std::io::SeekFrom::Start(0)).await?;

        let mut reader = BufReader::new(&mut *handler).lines();

        while let Some(line) = reader.next_line().await.inspect_err(|e| {
            eprintln!("Potentially corrupted DatabaseCommand in WAL file with: {e}.")
        })? {
            let command: DatabaseCommand = DatabaseCommand::deserialize(&line)?;
            buffer.push(command);
        }

        Ok(buffer)
    }

    async fn exec(&mut self, command: DatabaseCommand) -> Result<(), Box<dyn Error + Send + Sync>> {
        let WAL = self.get_wal();
        let mut WAL = WAL.lock().await;

        WAL.save_command(command).await?;

        if WAL.get_size() >= WAL_COMMAND_SIZE {
            self.execute_commands(WAL).await?;
        }

        Ok(())
    }

    /// Executes the commands on the WAL file. The reason why is it places inside the `Database` not the `DatabaseWAL`
    /// is because it persists the instances of the `DatabaseCollection`.
    ///
    /// Scenario in which Database does not have a collection instance inside `collections` field
    /// but it exists inside DatabaseWAL SHOULD NOT happen, as the WAL file gets flushed on the server shutdown.
    async fn execute_commands(
        &mut self,
        WAL: MutexGuard<'_, DatabaseWAL>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // let WAL = self.get_wal();
        // let WAL = WAL.lock().await;

        let handler = WAL.get_handler();
        let size = WAL.get_size();

        // Release the previous lock as the below code also locks that Mutex.
        drop(WAL);

        let WAL_commands = Database::parse_WAL(handler, size).await?;

        let mut storage: HashMap<DatabaseType, DatabaseStorage<Box<dyn DatabaseEntryTrait>>> =
            self.parse_WAL_collections().await?;

        for command in WAL_commands {
            // TODO: If Logger would be implemented I would want to log the result of that.
            match command {
                DatabaseCommand::Insert(d_type, entry) => self._insert(&mut storage, entry, d_type),
                DatabaseCommand::Update(d_type, id, entry) => {
                    self._update(&mut storage, id, entry, d_type)
                }
                DatabaseCommand::Delete(d_type, id) => self._delete(&mut storage, id, d_type),
                // Select and SelectAll are commands that cannot be buffered in the WAL file, invocation of those makes the WAL commands flushed
                // to provide stateful output.
                _ => Err("Unsupported command.")?,
            }?;
        }

        self.save_commands_execution(&storage).await?;

        let WAL = self.get_wal();
        let WAL = WAL.lock().await;

        WAL.reset_size().await?;

        return Ok(());
    }

    async fn save_commands_execution(
        &self,
        storage: &HashMap<DatabaseType, DatabaseStorage<Box<dyn DatabaseEntryTrait>>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        for (d_type, collection_storage) in storage.iter() {
            let collection = self.get_collection(d_type.clone()).unwrap();
            let collection = collection.lock().await;
            collection
                .overwrite_database_file(collection_storage)
                .await?;
        }

        println!("Write-ahead log file has been flushed to the disk.");

        Ok(())
    }

    /// Creates a new collection for the given `DatabaseType` and inserts it into the `collections` HashMap.
    pub async fn create_collection(
        &mut self,
        config: &DatabaseConfigEntry,
        d_type: DatabaseType,
    ) -> Result<Arc<Mutex<DatabaseCollection>>, Box<dyn Error + Send + Sync>> {
        let collection = DatabaseCollection::new(config, &d_type).await?;
        let c_clone = Arc::clone(&collection);
        self.insert_collection(d_type, collection);

        Ok(c_clone)
    }

    /// Retrieves the collection for the given `DatabaseType`, if it exists, returns it.
    fn get_collection(&self, d_type: DatabaseType) -> Option<Arc<Mutex<DatabaseCollection>>> {
        self.collections.get(&d_type).map(|c| Arc::clone(c))
    }

    /// Retrieves the collection for the given `DatabaseType`, if it does not exist, creates it.
    pub async fn get_create_collection(
        &mut self,
        config: &DatabaseConfigEntry,
        d_type: DatabaseType,
    ) -> Result<Arc<Mutex<DatabaseCollection>>, Box<dyn Error + Send + Sync>> {
        match self.get_collection(d_type.clone()) {
            Some(collection) => Ok(collection),
            None => self.create_collection(&config, d_type).await,
        }
    }

    fn insert_collection(
        &mut self,
        d_type: DatabaseType,
        collection: Arc<Mutex<DatabaseCollection>>,
    ) {
        self.collections.insert(d_type, collection);
    }

    pub async fn insert(
        &mut self,
        d_type: DatabaseType,
        entry: &(impl AsRef<[u8]> + std::fmt::Debug),
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.exec(DatabaseCommand::Insert(d_type, DatabaseEntry::new(entry)))
            .await
    }

    pub async fn update(
        &mut self,
        id: &(impl AsRef<[u8]> + std::fmt::Debug),
        entry: &(impl AsRef<[u8]> + std::fmt::Debug),
        d_type: DatabaseType,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.exec(DatabaseCommand::Update(
            d_type,
            String::from_utf8(id.as_ref().to_vec()).map_err(|_| "Id is not a valid UTF-8")?,
            DatabaseEntry::new(entry),
        ))
        .await
    }

    pub async fn delete(
        &mut self,
        d_type: DatabaseType,
        id: &(impl AsRef<[u8]> + std::fmt::Debug),
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Id should come as a string, and what we get from the request is
        // a Vec<u8>, we take the reference to that vector, and since it implements that
        // trait we can use it as is and convert it to String.
        let id = String::from_utf8(id.as_ref().to_vec()).map_err(|_| "Id is not a valid UTF-8")?;

        self.exec(DatabaseCommand::Delete(d_type, id)).await
    }

    pub async fn select(
        &mut self,
        config: &DatabaseConfigEntry,
        d_type: DatabaseType,
        id: String,
    ) -> Result<Box<dyn DatabaseEntryTrait>, Box<dyn Error + Send + Sync>> {
        let WAL = self.get_wal();
        let WAL = WAL.lock().await;

        // To avoid unnecessary parsing of the WAL file, we will check if it is empty.
        if WAL.get_size() != 0 {
            // Flush the commands to the database file to provide stateful output.
            self.execute_commands(WAL).await?;
        }

        // Collection could not have been created if WAL did not flush.
        let d_type = d_type.clone();
        let collection = self.get_create_collection(config, d_type).await?;
        let collection = collection.lock().await;

        let storage = collection.parse_collection().await?;
        let entry = storage
            .get(&id)
            .ok_or(format!("Entry with the provided id: {id} does not exists."))?;

        // essentially javascript out there, how the mediocre have fallen.
        let entry = if let Some(entry) = entry.as_any().downcast_ref::<DatabaseTask>() {
            Box::new(entry.clone()) as Box<dyn DatabaseEntryTrait>
        } else if let Some(entry) = entry.as_any().downcast_ref::<DatabaseUser>() {
            Box::new(entry.clone()) as Box<dyn DatabaseEntryTrait>
        } else {
            return Err("Invalid entry type".into());
        };

        Ok(entry)
    }

    pub async fn select_all(
        &mut self,
        d_type: DatabaseType,
        config: &DatabaseConfigEntry,
    ) -> Result<DatabaseStorage<Box<dyn DatabaseEntryTrait>>, Box<dyn Error + Send + Sync>> {
        let WAL = self.get_wal();
        let WAL = WAL.lock().await;

        // To avoid unnecessary parsing of the WAL file, we will check if it is empty.
        if WAL.get_size() != 0 {
            // Flush the commands to the database file to provide stateful output.
            self.execute_commands(WAL).await?;
        }

        // Collection has to be created before we can parse it, but they are not initialized until the WAL file is flushed,
        // so we need to explicitly initialize it if not initialized yet.
        let d_type = d_type.clone();
        let collection = self.get_create_collection(config, d_type).await?;
        let collection = collection.lock().await;

        let storage = collection.parse_collection().await?;

        Ok(storage)
    }

    // We could make those methods defined on `DatabaseCollection` but that would require as to lock the Mutex every time we want to access the collection
    // Also, that would not provide any customizable functionality for those methods, that would be just a wrapper.

    fn _insert(
        &self,
        storage: &mut HashMap<DatabaseType, DatabaseStorage<Box<dyn DatabaseEntryTrait>>>,
        entry: DatabaseEntry,
        d_type: DatabaseType,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Retrieves the collection from the storage
        let collection = storage.get_mut(&d_type).unwrap();

        // Serializes the Vec<u8> to the Box<dyn DatabaseEntryTrait>, tagging the type of the entry
        // to allow the deserialization to the correct type.
        let entry = entry.parse(d_type)?;

        let id = entry.get_id();

        if collection.contains_key(&id) {
            return Err("Entry with the same id already exists.".into());
        }

        // Save the parsed entry to the collection
        collection.insert(id, entry);

        Ok(())
    }

    /// Replaces the entry given by the `id` with the new entry.
    /// update is the same as insert as we just overwriting the entry in the collection.
    fn _update(
        &self,
        storage: &mut HashMap<DatabaseType, DatabaseStorage<Box<dyn DatabaseEntryTrait>>>,
        id: String,
        entry: DatabaseEntry,
        d_type: DatabaseType,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Retrieves the collection from the storage
        let collection = storage.get_mut(&d_type).unwrap();

        // Serializes the Vec<u8> to the Box<dyn DatabaseEntryTrait>
        let entry = entry.parse(d_type)?;

        // let id = entry.get_id();

        if !collection.contains_key(&id) {
            return Err(format!("Entry with the provided id: {id} does not exists.").into());
        }

        // Save the parsed entry to the collection
        collection.insert(id, entry);

        Ok(())
    }

    fn _delete(
        &self,
        storage: &mut HashMap<DatabaseType, DatabaseStorage<Box<dyn DatabaseEntryTrait>>>,
        id: String,
        d_type: DatabaseType,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Retrieves the collection from the storage
        let collection = storage.get_mut(&d_type).unwrap();

        if !collection.contains_key(&id) {
            return Err(format!("Entry with the provided id: {id} does not exists.").into());
        }

        // Deletes the entry from the collection
        collection.remove(&id);

        Ok(())
    }

    fn get_wal(&self) -> Arc<Mutex<DatabaseWAL>> {
        Arc::clone(&self.WAL)
    }
}

#[derive(Debug, Clone)]
pub struct DatabaseCollection {
    /// Type of the database, used to determine which database to use when writing the data to the file system.
    d_type: DatabaseType,
    /// File handle to the underlying storage, written when first invoked with Self::.
    handler: Option<Arc<Mutex<File>>>,
}

impl DatabaseCollection {
    async fn new(
        config: &DatabaseConfigEntry,
        d_type: &DatabaseType,
    ) -> Result<Arc<Mutex<Self>>, Box<dyn Error + Send + Sync>> {
        Ok(Arc::new(Mutex::new(Self {
            handler: Some(Self::open_database_file(config, &d_type).await?),
            d_type: d_type.clone(),
        })))
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
        let path = Self::create_path(config, d_type).await;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .await?;

        // NOTE: This check is useless if the file was just created, but we can't know that without checking.
        if file.metadata().await?.len() == 0 {
            file.write(b"{}").await?;
            file.flush().await?;
        }

        // NOTE: Cursor shifts does not persists across Arc<Mutex<T>>,
        // we have to call it explicitly before writing
        // file.seek(std::io::SeekFrom::Start(0)).await?;

        Ok(Arc::new(Mutex::new(file)))
    }

    async fn overwrite_database_file(
        &self,
        data: &DatabaseStorage<Box<dyn DatabaseEntryTrait>>,
        // d_type: &DatabaseType,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Hold entries as raw data instead of deserialized instances of `dyn DatabaseEntryTrait`
        let data = serde_json::to_string(
            &data
                .iter()
                .map(|(k, v)| (k.to_string(), v.serialize()))
                .collect::<std::collections::HashMap<_, _>>(),
        )?;

        let serialized = serde_json::to_vec(&data)?;

        let handler = self.get_handler();
        let mut handler = handler.lock().await;

        handler.seek(std::io::SeekFrom::Start(0)).await?;
        handler.set_len(0).await?;
        handler.write_all(&serialized).await?;

        Ok(())
    }

    /// Parses the collection file to the `HashMap<String, Box<dyn DatabaseEntryTrait>>` type.
    async fn parse_collection(
        &self,
    ) -> Result<DatabaseStorage<Box<dyn DatabaseEntryTrait>>, Box<dyn Error + Send + Sync>> {
        let handler = self.get_handler();
        let mut handler = handler.lock().await;
        let mut buffer = Vec::new();

        handler.seek(std::io::SeekFrom::Start(0)).await?;
        let bytes_read = handler.read_to_end(buffer.as_mut()).await?;

        // NOTE: This should never happens as even empty file has "{}" in it.
        if bytes_read == 0 {
            return Err("Empty file".into());
        }

        let deserializer = &mut serde_json::Deserializer::from_slice(&buffer);
        let format = &mut Box::new(<dyn Deserializer>::erase(deserializer));

        // Statically evaluate the type of Schema of the collection and parse it.
        Ok(match self.d_type {
            DatabaseType::Users => {
                erased_serde::deserialize::<DatabaseStorage<DatabaseUser>>(format)
                    .inspect_err(|e| eprintln!("Failed to deserialize DatabaseStorage: {e}"))?
                    .into_iter()
                    .map(|(k, v)| (k, Box::new(v) as Box<dyn DatabaseEntryTrait>))
                    .collect()
            }
            DatabaseType::Tasks => {
                erased_serde::deserialize::<DatabaseStorage<DatabaseTask>>(format)
                    .inspect_err(|e| eprintln!("Failed to deserialize DatabaseStorage: {e}"))?
                    .into_iter()
                    .map(|(k, v)| (k, Box::new(v) as Box<dyn DatabaseEntryTrait>))
                    .collect()
            }
        })
    }

    /// Clones the reference Arc type, increasing the reference count
    ///
    /// Unwraps the handler, if you'll delete the file during the runtime, it will panic, but that's on you.
    /// Will be fine on server restart, as the file will be recreated.
    fn get_handler(&self) -> Arc<Mutex<File>> {
        Arc::clone(&self.handler.as_ref().unwrap())
    }
}

/// The `DatabaseType` describes which `DatabaseCollection` to initialize, it would stay unutilized until constructed.
///
/// Enum naming reflect the file name of the underlying database as lowercase, it will automatically
/// create databases filenames with defined enum variants.
///
/// `TODO`: Provide opting out of the behavior of automatically creating the database with provided enum names
/// and allow to supply it's own database name instead using the one defined as an enum variant
#[derive(
    Debug,
    // EnumIter,
    serde::Serialize,
    serde::Deserialize,
    strum_macros::Display,
    Clone,
    Eq,
    PartialEq,
    Hash,
)]
// If Tasks would be user specific, that would provide separation between users tasks, currently it just does not make any sense,
// as everyone shares the same tasks.
// QUESTION: How would database WAL look-like?
// ANSWER: Currently DatabaseCommand just takes the collection type and entry, sometimes additionally the id for updates.
//  => We would have to map also the id of the user that posted the content, then build a filename essentially as
//  => the collection is just a file but suffix that with "-{user_id}", eg. "tasks-1234.json", that would be done
//  => when we create the collection, currently we are creating collections when flushing the WAL file.
//  => DatabaseCommand would look like: DatabaseCommand::Insert(DatabaseType, String, DatabaseEntry, Option<String>),
//  => that is the easy version, would require many changes to the code, essentially even the constructor of the
//  => DatabaseCollection would have to take the user id as an argument.
//  => Given that when user is logged, his API key is carried over the requests, we could somehow utilize that.
//  =>

// #[serde(rename_all = "lowercase")]
pub enum DatabaseType {
    Users,
    Tasks,
}

/// Stores the write-ahead log file for each `DatabaseType`, is `DatabaseCollection` agnostic.
/// Currently initialization is done in the `Config` constructor, and stored there for the duration of the program.
///
/// Not really fully fledged write-ahead logging
/// log will be in a text format, thought entries will be written per line in the JSON format
/// so to avoid parsing the whole file of database collection every time we want to write the entry
#[derive(Debug)]
struct DatabaseWAL {
    handler: Arc<Mutex<File>>,
    size: Arc<AtomicUsize>,
    /// Used to keep track of the `DatabaseType`s is the WAL file for parsing to avoid later iteration.
    d_types: HashSet<DatabaseType>,
}

/// The size of the WAL file, when it reaches that size, it will be flushed to the database file.
/// Greater in size the better performance, may result with higher memory usage, but I think it's negligible.
///
/// There is also possibility to opt-out of slushing on certain size, do it only on commands
/// like select, select_all to provide stateful output, but otherwise just flush it on shutdown.
/// To opt-out set it to max value of `usize`.
const WAL_COMMAND_SIZE: usize = 100;

impl DatabaseWAL {
    async fn new(
        config: &DatabaseConfigEntry,
    ) -> Result<Arc<Mutex<DatabaseWAL>>, Box<dyn Error + Send + Sync>> {
        Ok(Arc::new(Mutex::new(DatabaseWAL {
            handler: Self::open_file(&config).await?,
            size: Arc::new(AtomicUsize::new(0)),
            d_types: HashSet::new(),
        })))
    }

    /// Loads the state of the WAL file and parses it to instance of `DatabaseWAL`.
    /// Could happen when server closes abruptly and we need to restore the state of the `DatabaseWAL` instance.
    async fn load_state(
        config: &DatabaseConfigEntry,
    ) -> Result<Option<Arc<Mutex<Self>>>, Box<dyn Error + Send + Sync>> {
        let handler = DatabaseWAL::open_file(config).await?;
        let c = Arc::clone(&handler);

        if let Ok(result) = fs::try_exists(&config.WAL).await {
            if result {
                let metadata = fs::metadata(&config.WAL).await?;

                if metadata.len() != 0 {
                    let commands = Database::parse_WAL(c, 0).await?;
                    let size = commands.len();
                    let d_types =
                        commands
                            .iter()
                            .fold(HashSet::<DatabaseType>::new(), |mut acc, ele| {
                                acc.insert(ele.get_database_type().clone());
                                acc
                            });

                    return Ok(Some(Arc::new(Mutex::new(DatabaseWAL {
                        handler,
                        size: Arc::new(AtomicUsize::new(size)),
                        d_types,
                    }))));
                }
            }
        };

        // We want a pattern of Result<Option<T>> for it to not trigger and error if there is no unprocessed commands in the WAL file.
        // as it is not technically an error.
        Ok(None)
    }

    /// Opens file handle to the underling write-ahead log or creates if not exists.
    async fn open_file(
        config: &DatabaseConfigEntry,
    ) -> Result<Arc<Mutex<File>>, Box<dyn Error + Send + Sync>> {
        // Create the logging file for the commands
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .read(true)
            .open(&config.WAL)
            .await?;

        Ok(Arc::new(Mutex::new(file)))
    }

    /// Executes the command on the WAL file,
    async fn save_command(
        &mut self,
        command: DatabaseCommand,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Below we will write the actual entry to the WAL file.

        let file = self.get_handler();
        let mut file = file.lock().await;

        let mut command_json = serde_json::to_string(&command)?;
        command_json.push_str("\r\n");

        let command_json = command_json.as_bytes();

        file.write_all(command_json).await?;
        file.flush().await?;

        self.add_d_type(command.get_database_type().clone());
        self.increment_size();

        Ok(())
    }

    fn get_handler(&self) -> Arc<Mutex<File>> {
        Arc::clone(&self.handler)
    }

    fn get_size(&self) -> usize {
        self.size.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn increment_size(&self) {
        self.size.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Resets the size of `size` field to 0 and the size of the WAL file to 0.
    async fn reset_size(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let file = self.get_handler();
        let mut file = file.lock().await;

        file.set_len(0)
            .await
            .inspect_err(|_| eprintln!("Failed to reset the size of WAL file."))?;

        file.seek(std::io::SeekFrom::Start(0))
            .await
            .inspect_err(|_| eprintln!("Failed to reset the size of WAL file."))?;

        self.size.store(0, std::sync::atomic::Ordering::SeqCst);

        Ok(())
    }

    fn add_d_type(&mut self, collection: DatabaseType) {
        self.d_types.insert(collection);
    }

    fn get_d_types(&self) -> &HashSet<DatabaseType> {
        &self.d_types
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
/// IO buffered commands executed on the database, on system shutdown or 100 commands in the buffer (memory or WAL file I think).
enum DatabaseCommand {
    /// Insert one entry to given DatabaseType with a new entry
    Insert(DatabaseType, DatabaseEntry),
    /// Update one entry to given DatabaseType with a new entry
    Update(DatabaseType, String, DatabaseEntry),
    /// Delete one entry to given DatabaseType
    Delete(DatabaseType, String),
    // Select and SelectAll are commands that cannot be buffered in the WAL file,
    // as they are not trigger the side effect on database, so they will not be stored in the WAL file
    // if executed, but evaluated eagerly and they will also trigger the execution of the buffered commands as if not, the result could be stale.
    /// Select one entry to given DatabaseType
    Select(DatabaseType, String),
    /// Select everything to given DatabaseType
    SelectAll(DatabaseType),
}

impl DatabaseCommand {
    fn get_database_type(&self) -> &DatabaseType {
        use DatabaseCommand::*;
        match self {
            Insert(dt, _) | Update(dt, _, _) | Delete(dt, _) | Select(dt, _) | SelectAll(dt) => dt,
        }
    }

    fn deserialize(entry: &impl AsRef<[u8]>) -> Result<Self, serde_json::Error> {
        serde_json::from_slice::<Self>(entry.as_ref())
            .inspect_err(|e| eprintln!("Failed to deserialize DatabaseCommand: {e}"))
    }
}
