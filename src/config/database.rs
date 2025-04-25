/*
    ### What started as a joke, remained one ###
    NOTE: That was does purely for educational purposes, I would not recommend using this in production as it's file system based database and reinvented wheel (rectangular one).
*/

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

use crate::config::{config_file::DatabaseConfigEntry, Config};
use crate::prelude::*;
use erased_serde::Deserializer;
use rand::prelude::*;
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::atomic::AtomicUsize;
use std::{path::PathBuf, sync::Arc};
use strum_macros::EnumIter;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::sync::MutexGuard;
use tokio::{
    fs::File,
    io::{AsyncSeekExt, AsyncWriteExt},
};

#[typetag::serde]
pub trait DatabaseEntryTrait: Send + Sync + Debug + Any {
    fn as_any(&self) -> &dyn Any;
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct DatabaseTask {
    value: String,
    id: u32,
}

#[typetag::serde]
impl DatabaseEntryTrait for DatabaseTask {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct DatabaseUser {
    name: String,
    id: u32,
}

#[typetag::serde]
impl DatabaseEntryTrait for DatabaseUser {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct DatabaseEntry(Vec<u8>);

#[typetag::serde]
impl DatabaseEntryTrait for DatabaseEntry {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl DatabaseEntry {
    // NOTE: Maybe bytes: &[u8] would be better.
    fn new(bytes: &impl AsRef<[u8]>) -> Self {
        DatabaseEntry(bytes.as_ref().to_vec())
    }

    /// Deserializes the entry to the actually type behind the trait object of `DatabaseEntryTrait` defined with `Box<dyn DatabaseEntryTrait>`.
    ///
    /// `NOTE`: This function is `STATIC` and would require change in definition if new `DatabaseType` would be added.
    fn parse(
        &self,
        d_type: DatabaseType,
    ) -> Result<Box<dyn DatabaseEntryTrait>, Box<dyn Error + Send + Sync>> {
        Ok(match d_type {
            // I think there will be error because DatabaseUser and DatabaseTask declared macro of `typetag::serde`,
            // so deserializer will expect the tag type which is not present as the data we are deserializing was not
            // previously serialized, so was never tagged.
            DatabaseType::Users => Box::new(serde_json::from_slice::<DatabaseUser>(&self.0)?),
            DatabaseType::Tasks => Box::new(serde_json::from_slice::<DatabaseTask>(&self.0)?),
        })
    }
}

// bounds on generic parameters in type aliases are not enforced
// this is a known limitation of the type checker that may be lifted in a future edition.
// see issue #112792 <https://github.com/rust-lang/rust/issues/112792> for more information
// `#[warn(type_alias_bounds)]` on by default
// T: DatabaseEntryTrait => T
type DatabaseStorage<T> = HashMap<usize, T>;

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
        Ok(Self {
            collections: HashMap::new(),
            WAL: Arc::new(Mutex::new(DatabaseWAL::new(&config).await.inspect_err(
                |_| eprintln!("DatabaseWAL could not be initialized."),
            )?)),
            // I do not mind cloning as those are just 2 PathBuf's.
            _database_config_entry: config.clone(),
        })
    }

    /// Parses the collections occurring in the WAL file to the `HashMap<DatabaseType, DatabaseStorage<Box<dyn DatabaseEntryTrait>>>` type.
    async fn parse_WAL_collections(
        &mut self,
        // collections: &HashSet<DatabaseType>,
    ) -> Result<
        HashMap<DatabaseType, DatabaseStorage<Box<dyn DatabaseEntryTrait>>>,
        Box<dyn Error + Send + Sync>,
    > {
        let mut storage = HashMap::new();

        let WAL = self.get_wal();
        let WAL = WAL.lock().await;

        let collections = WAL.get_collections();
        let config = self._database_config_entry.clone();

        for collection_type in collections {
            let collection = self
                .get_create_collection(&config, collection_type.clone())
                .await?;
            let collection = collection.lock().await;
            let collection = collection.parse_collection().await?;

            storage.insert(collection_type.clone(), collection);
        }

        Ok(storage)
    }

    /// Deserializes the WAL file to the `Vec` of raw commands, just as they were written.
    ///
    /// `NOTE`: WAL has to be passed through the function as deadlock occurs without it.
    async fn parse_wal(
        &self,
        WAL: MutexGuard<'_, DatabaseWAL>,
    ) -> Result<Vec<DatabaseCommand>, Box<dyn Error + Send + Sync>> {
        let file = WAL.get_handler();

        let mut file = file.lock().await;
        let mut buffer = Vec::<DatabaseCommand>::with_capacity(WAL.get_size());

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

    async fn exec(&mut self, command: DatabaseCommand) -> Result<(), Box<dyn Error + Send + Sync>> {
        let WAL = self.get_wal();
        let mut WAL = WAL.lock().await;

        if WAL.get_size() >= WAL_COMMAND_SIZE {
            self.execute_commands(WAL).await?;
        } else {
            WAL.save_command(command).await?;
        }

        Ok(())
    }

    /// Executes the commands on the WAL file. The reason why is it places inside the `Database` not the `DatabaseWAL`
    /// is because it persists the instances of the `DatabaseCollection`.
    ///
    /// Scenario in which Database does not have a collection instance inside `collections` field
    /// but it exists inside DatabaseWAL SHOULD NOT happen, as the WAL file gets flushed on the server shutdown.
    ///
    /// `TODO`: Thought being honest it should support that use cases if it crashes abruptly.
    async fn execute_commands(
        &mut self,
        WAL: MutexGuard<'_, DatabaseWAL>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let WAL_commands = self.parse_wal(WAL).await?;

        let mut storage: HashMap<DatabaseType, DatabaseStorage<Box<dyn DatabaseEntryTrait>>> =
            self.parse_WAL_collections().await?;

        for command in WAL_commands {
            // TODO: If Logger would be implemented I would want to log the result of that.
            match command {
                DatabaseCommand::Insert(d_type, entry) => self._insert(&mut storage, entry, d_type),
                DatabaseCommand::Update(d_type, entry) => self._update(&mut storage, entry, d_type),
                DatabaseCommand::Delete(d_type, id) => self._delete(&mut storage, id, d_type),
                // Select and SelectAll are commands that cannot be buffered in the WAL file, invocation of those makes the WAL commands flushed
                // to provide stateful output.
                _ => Err("Unsupported command.")?,
            }?;
        }

        // NOTE: After the execution of the commands we should serialize the storage and write it to appropriate files.
        // Based on the `DatabaseType` of the `storage` we will retrieve the collection via `get_collection` method
        // Then we will serialize the value of `DatabaseStorage<Box<dyn DatabaseEntryTrait>>` to the file.
        // That would be a little bit tricky as it is behind trait object. Consider using `typetag`

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
        println!("storage: {:#?}", storage);

        for (d_type, collection_storage) in storage.iter() {
            let collection = self.get_collection(d_type.clone()).unwrap();
            let collection = collection.lock().await;
            collection
                .overwrite_database_file(collection_storage)
                .await?;
        }

        Ok(())
    }

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

    fn get_collection(&self, d_type: DatabaseType) -> Option<Arc<Mutex<DatabaseCollection>>> {
        self.collections.get(&d_type).map(|c| Arc::clone(c))
    }

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
        entry: &(impl AsRef<[u8]> + std::fmt::Debug),
        d_type: DatabaseType,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.exec(DatabaseCommand::Insert(d_type, DatabaseEntry::new(entry)))
            .await
    }

    pub async fn update(
        &mut self,
        entry: &(impl AsRef<[u8]> + std::fmt::Debug),
        d_type: DatabaseType,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.exec(DatabaseCommand::Update(d_type, DatabaseEntry::new(entry)))
            .await
    }

    pub async fn delete(
        &mut self,
        d_type: DatabaseType,
        id: usize,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.exec(DatabaseCommand::Delete(d_type, id)).await
    }

    pub async fn select<'a>(
        &mut self,
        d_type: DatabaseType,
        id: usize,
    ) -> Result<Box<dyn DatabaseEntryTrait>, Box<dyn Error + Send + Sync>> {
        let WAL = self.get_wal();
        let mut WAL = WAL.lock().await;

        // To avoid unnecessary parsing of the WAL file, we will check if it is empty.
        if WAL.get_size() == 0 {
            // Flush the commands to the database file to provide stateful output.
            self.execute_commands(WAL).await?;
        }

        let collection = self.get_collection(d_type.clone()).unwrap();
        let collection = collection.lock().await;

        let storage = collection.parse_collection().await?;
        let entry = storage.get(&id).unwrap();

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
    ) -> Result<DatabaseStorage<Box<dyn DatabaseEntryTrait>>, Box<dyn Error + Send + Sync>> {
        let WAL = self.get_wal();
        let mut WAL = WAL.lock().await;

        // To avoid unnecessary parsing of the WAL file, we will check if it is empty.
        if WAL.get_size() == 0 {
            // Flush the commands to the database file to provide stateful output.
            self.execute_commands(WAL).await?;
        }

        let collection = self.get_collection(d_type.clone()).unwrap();
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

        // NOTE: That should not be random, but client defined, the id that is in the entry
        // should be used there as the primary key, otherwise something like select would not work.

        let mut rng = rand::rng();
        let nums: Vec<usize> = (1..100).collect();

        // And take a random pick (yes, we didn't need to shuffle first!):

        // NOTE: That should be somehow generated.
        let id = nums.choose(&mut rng).expect("Failed to choose random id.");

        // Save the parsed entry to the collection
        collection.insert(*id, entry);

        Ok(())
    }

    /// update is the same as insert as we just overwriting the entry in the collection.
    fn _update(
        &self,
        storage: &mut HashMap<DatabaseType, DatabaseStorage<Box<dyn DatabaseEntryTrait>>>,
        entry: DatabaseEntry,
        d_type: DatabaseType,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self._insert(storage, entry, d_type)
    }

    fn _delete(
        &self,
        storage: &mut HashMap<DatabaseType, DatabaseStorage<Box<dyn DatabaseEntryTrait>>>,
        id: usize,
        d_type: DatabaseType,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Retrieves the collection from the storage
        let collection = storage.get_mut(&d_type).unwrap();

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
            // WAL: Arc::clone(WAL),
            handler: Some(Self::open_database_file(config, &d_type).await?),
            d_type: d_type.clone(),
        })))
    }

    /// Constructs path to database using `DatabaseType` enum variant which converts to string
    /// in lowercase fashion.
    ///
    /// Does not confirm the file existence.
    async fn create_path(config: &DatabaseConfigEntry, segment: &DatabaseType) -> PathBuf {
        // Safe to unwrap based on previous check in the Config::new
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

        // NOTE: This check is useless if the file was just created
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
        // NOTE: Should be Vec<Box<dyn DatabaseEntryTrait>>
        data: &HashMap<usize, Box<dyn DatabaseEntryTrait>>,
        // d_type: &DatabaseType,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // let serializer = &mut serde_json::Serializer::new(Vec::<u8>::new());
        // let format = &mut Box::new(<dyn Serializer>::erase(serializer));

        // let data = data.erased_serialize(format).unwrap();

        let serialized = serde_json::to_vec(data)?;

        let handler = self.get_handler();
        let mut handler = handler.lock().await;

        handler.seek(std::io::SeekFrom::Start(0)).await?;
        handler.set_len(0).await?;
        handler.write_all(&serialized).await?;

        // match self.d_type {
        //     DatabaseType::Users => {
        //         let mut handler = self.get_handler();
        //         let mut handler = handler.lock().await;

        //         handler.seek(std::io::SeekFrom::Start(0)).await?;
        //         handler.set_len(0).await?;
        //         handler.write_all(&serialized).await?;
        //     }
        //     DatabaseType::Tasks => todo!(),
        // }

        Ok(())
    }

    /// Parses the collection file to the `HashMap<usize, Box<dyn DatabaseEntryTrait>>` type.
    async fn parse_collection(
        &self,
    ) -> Result<DatabaseStorage<Box<dyn DatabaseEntryTrait>>, Box<dyn Error + Send + Sync>> {
        let handler = self.get_handler();
        let mut handler = handler.lock().await;
        let mut buffer = Vec::new();

        handler.seek(std::io::SeekFrom::Start(0)).await?;
        let bytes_read = handler.read_to_end(buffer.as_mut()).await?;

        // NOTE: This should never happens even empty file has "{}" in it.
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
/// `NOTE`: Enum naming reflect the file name of the underlying database as lowercase, it will automatically
/// create databases filenames with defined enum variants.
///
/// `TODO`: Provide opting out of the behavior of automatically creating the database with provided enum names
/// and allow to supply it's own database name instead using the one defined as an enum variant
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

/// Stores the write-ahead log file for each `DatabaseType`, is `DatabaseType` agnostic.
/// Currently initialization is done in the `Config` constructor, and stored there for the duration of the program.
///
/// `NOTE`: Not really fully fledged write-ahead logging
/// log will be in a text format, thought entries will be written per line in the JSON format
/// so to avoid parsing the whole file of database collection every time we want to write the entry
///
/// `NOTE`: That could not hold a schema because it is database agnostic, meaning it should holds multiple types of data and parses
#[derive(Debug)]
/// to the correct type when executing the command
struct DatabaseWAL {
    handler: Arc<Mutex<File>>,
    size: Arc<AtomicUsize>,
    /// Used to keep track of the collections is the WAL file for parsing to avoid later iteration.
    ///
    /// `TODO`: That actually stores DatabaseType and we should resolved that ambiguity.
    _collections: HashSet<DatabaseType>,
}

const WAL_COMMAND_SIZE: usize = 100;

impl DatabaseWAL {
    /// NOTE: This function should be invoked only
    async fn new(
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

    /// Executes the command on the WAL file,
    async fn save_command(
        &mut self,
        command: DatabaseCommand,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        // Below we will write the actual entry to the WAL file.

        let file = self.get_handler();
        let mut file = file.lock().await;

        let mut command_json = serde_json::to_string(&command)?;
        command_json.push_str("\r\n");

        let command_json = command_json.as_bytes();

        file.write_all(command_json).await?;
        file.flush().await?;

        self.add_collection(command.get_database_type().clone());
        self.increment_size();

        Ok(String::new())
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

    fn decrement_size(&self) {
        self.size.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Resets the size of `size` field to 0 and the size of the WAL file to 0.
    async fn reset_size(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let file = self.get_handler();
        let file = file.lock().await;

        file.set_len(0)
            .await
            .inspect_err(|_| eprintln!("Failed to reset the size of WAL file."))?;

        self.size.store(0, std::sync::atomic::Ordering::SeqCst);

        Ok(())
    }

    fn add_collection(&mut self, collection: DatabaseType) {
        self._collections.insert(collection);
    }

    fn get_collections(&self) -> &HashSet<DatabaseType> {
        &self._collections
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
/// IO buffered commands executed on the database, on system shutdown or 100 commands in the buffer (memory or WAL file I think).
///
/// `NOTE`: I think DatabaseType is useless as Database instance already has the `d_type` fields with that, we could use that to write to the WAL
/// file for later parsing, but current implementation may be easier.
///
/// `TODO`: Commands like Select, SelectAll should trigger the `Database::exec` as that would could produce stale data if we wouldn't do that.
///
/// `NOTE`: Schema potentially useless as it's not getting written in the WAL file, so either way we do not how to parse it.
enum DatabaseCommand {
    /// Insert one entry to given DatabaseType with a new entry
    Insert(DatabaseType, DatabaseEntry),
    /// Update one entry to given DatabaseType with a new entry
    Update(DatabaseType, DatabaseEntry),
    /// Delete one entry to given DatabaseType
    Delete(DatabaseType, usize),
    // Select and SelectAll are commands that cannot be buffered in the WAL file,
    // as they are not trigger the side effect on database, so they will not be stored in the WAL file
    // if executed, but evaluated eagerly and they will also trigger the execution of the buffered commands as if not, the result could be stale.
    /// Select one entry to given DatabaseType
    Select(DatabaseType, usize),
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
    fn get_database_type(&self) -> &DatabaseType {
        use DatabaseCommand::*;
        match self {
            Insert(dt, _) | Update(dt, _) | Delete(dt, _) | Select(dt, _) | SelectAll(dt) => dt,
        }
    }

    fn deserialize(entry: &impl AsRef<[u8]>) -> Result<Self, serde_json::Error> {
        serde_json::from_slice::<Self>(entry.as_ref())
            .inspect_err(|e| eprintln!("Failed to deserialize DatabaseCommand: {e}"))
    }
}
