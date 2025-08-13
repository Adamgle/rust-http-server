use crate::config::Config;
use crate::config::config_file::DatabaseConfigEntry;
use crate::config::database::{DatabaseCommand, DatabaseWAL};
use crate::http::HttpRequestError;
use crate::prelude::*;

use serde_json;
use std::any::Any;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Debug;
use std::path::PathBuf;
use std::time::SystemTimeError;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

// / We are using Strings as the keys to store uuids.
type DatabaseStorage<T> = HashMap<String, T>;

#[derive(Debug)]
pub struct DatabaseCollections {
    /// The collections that are currently in the database.
    /// Those are the collections that are currently in the WAL file, and not yet flushed to the database file.
    /// This is used to avoid parsing the WAL file every time we want to get a collection.
    collections: DatabaseStorage<Arc<Mutex<DatabaseCollection>>>,
    WAL: Arc<Mutex<DatabaseWAL>>,
    /// That is clone of the database config entry, so we can access the database config without having to pass it around.
    config: DatabaseConfigEntry,
}

impl DatabaseCollections {
    pub async fn new(config: DatabaseConfigEntry) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Flush the buffered commands on the server startup, if any.
        if let Some(WAL) = DatabaseWAL::load_state(&config).await? {
            let mut instance = Self {
                collections: DatabaseStorage::new(),
                config: config.clone(),
                WAL,
            };

            instance.flush().await?;

            return Ok(instance);
        }

        Ok(Self {
            collections: DatabaseStorage::new(),
            WAL: DatabaseWAL::new(&config)
                .await
                .expect("DatabaseWAL could not be initialized."),
            config,
        })
    }

    /// Creates a new collection with the given name and returns it. If it exists, it returns the existing collection.
    ///
    /// Returns parsed collection.
    pub async fn get(
        &mut self,
        collection_name: &str,
    ) -> Result<Arc<Mutex<DatabaseCollection>>, Box<dyn Error + Send + Sync>> {
        let collection_name = collection_name.to_lowercase();

        let collection = if let Some(collection) = self.collections.get(&collection_name) {
            Arc::clone(&collection)
        } else {
            DatabaseCollection::new(&self.config, &collection_name).await?
        };

        let c = Arc::clone(&collection);
        let mut collection = collection.lock().await;

        if let None = collection.data {
            collection.parse_collection().await?;
        }

        self.collections
            .insert(collection_name.to_string(), Arc::clone(&c));

        return Ok(c);
    }

    /// Parses the collections occurring in the WAL file to the `HashMap<String, DatabaseStorage<DatabaseEntry>>` type.
    async fn parse_collections(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let WAL = Arc::clone(&self.WAL);
        let WAL = WAL.lock().await;

        let collection_names = WAL.get_collection_names();

        for collection_name in collection_names {
            // That is kinda ambiguous, but the get method parses and returns the collection. If it does not exist, it creates it.
            // but here we know it exists. It is done this way as whenever we are accessing the collection, we want it to be parsed.
            // so it makes sense to wrap the parse inside, and the collection is parsed only when the WAL is flushed, since we are
            // explicitly declaring the parsing function, as it is not by default. We don't need to worry about keeping it synced with what happens
            // in the actual collection file, as it is cleared after flush. NOTE: We could improve the performance by not clearing the data
            // but that would waste memory, also need to ensure that the data is not stale and CRUD it accordingly what happens on the actual collection file.
            let _ = self.get(collection_name).await?;
        }

        Ok(())
    }

    /// executes the commands on the WAL file. The reason why is it places inside the `Database` not the `DatabaseWAL`
    /// is because it persists the instances of the `DatabaseCollection`.
    ///
    /// Scenario in which Database does not have a collection instance inside `collections` field
    /// but it exists inside DatabaseWAL SHOULD NOT happen, as the WAL file gets flushed on the server shutdown.
    pub async fn flush(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let start_time = std::time::Instant::now();

        let instance = Arc::clone(&self.WAL);
        let WAL = instance.lock().await;

        if WAL.get_size() != 0 {
            let commands = DatabaseWAL::parse_WAL(WAL.get_handler(), WAL.get_size()).await?;

            drop(WAL);

            self.parse_collections().await?;

            for command in commands {
                let c = command.clone();
                if let Err(err) = match command {
                    DatabaseCommand::Insert { entry } => self._insert(entry).await,
                    DatabaseCommand::Update { entry, id } => self._update(entry, id).await,
                    DatabaseCommand::Delete {
                        collection_name,
                        id,
                    } => self._delete(&collection_name, id).await,

                    _ => Err("Unsupported command.")?,
                } {
                    error!("Failed to execute command: {:?}, error: {}", c, err);
                };
            }

            self.save_commands_execution().await?;

            let WAL = Arc::clone(&self.WAL);
            let WAL = WAL.lock().await;

            WAL.reset_size().await?;

            info!("Total flush time: {:?}", start_time.elapsed());
        }

        return Ok(());
    }

    async fn save_commands_execution(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Collect the keys into a vector to avoid borrowing issues
        let keys = self.collections.keys().cloned().collect::<Vec<String>>();

        for collection_name in keys {
            let collection = self.get(collection_name.as_ref()).await?;

            let mut collection: MutexGuard<'_, DatabaseCollection> = collection.lock().await;

            collection.overwrite_database_file().await?;

            // Clear the vector, we can remove this line and improve performance, but waste more memory as we would keep the entries in the RAM.
            // Some adjustments would be necessary if we would not want to clear the data.
            // Also it would make DatabaseWAL unnecessary as everything would be in-memory.
            // collection.data.clear();
            collection.data = None;
        }

        println!("Write-ahead log file has been flushed to the disk.");

        Ok(())
    }

    async fn execute(
        &mut self,
        command: DatabaseCommand,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let WAL = Arc::clone(&self.WAL);
        let mut WAL = WAL.lock().await;

        WAL.save_command(command).await?;

        if WAL.get_size() >= DatabaseWAL::WAL_COMMAND_SIZE {
            drop(WAL);

            self.flush().await?;
        }

        Ok(())
    }

    pub async fn insert<T, U>(
        &mut self,
        entry: &impl AsRef<[u8]>,
    ) -> Result<T, Box<dyn Error + Send + Sync>>
    where
        T: DatabaseEntryTrait + serde::Serialize + Clone + 'static,
        T: From<U>,
        U: serde::de::DeserializeOwned + serde::Serialize,
    {
        // Entry is tagged, so we have serialize it back to the bytes, it is tagged with the type of the entry.
        // That would internally validate the structure of the data that was passed from the client.

        // NOTE: This does not validate if the entry is of the correct type for the collection it is about to be inserted into.
        // All we know that we have the entry bytes that is tagged with the type of the entry, but those are information
        // derived from the statically declared generic types and it does validate if the entry bytes is in fact of that type.
        // Example: The entry could be of `DatabaseTask`, but the T and U could be `DatabaseUser` and `ClientUser` respectively,
        // it would satisfy the type constraints, but the entry bytes would not be of the correct type.

        // For entry type validity we are relying on the fact that if the parse would not fail, it is probably of the valid type.

        let e = T::parse::<U>(entry)?;

        self.execute(DatabaseCommand::Insert {
            entry: Box::new(e.clone()),
        })
        .await?;

        return Ok(e);
    }

    pub async fn update<T, U>(
        &mut self,
        entry: &impl AsRef<[u8]>,
        id: String,
    ) -> Result<T, Box<dyn Error + Send + Sync>>
    where
        T: DatabaseEntryTrait + serde::Serialize + Clone + 'static,
        T: From<U>,
        U: serde::de::DeserializeOwned + serde::Serialize,
    {
        let e = T::parse::<U>(entry)?;
        // let entry = DatabaseEntry::from(e.clone());

        self.execute(DatabaseCommand::Update {
            entry: Box::new(e.clone()),
            id,
        })
        .await?;

        Ok(e)
    }

    pub async fn delete(
        &mut self,
        collection_name: &str,
        id: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.execute(DatabaseCommand::Delete {
            // entry: Box::new(e.clone()),
            collection_name: collection_name.to_string(),
            id: id.to_string(),
        })
        .await?;

        Ok(())
    }

    pub async fn select<T, U>(
        &mut self,
        collection_name: &str,
        id: &str,
    ) -> Result<T, Box<dyn Error + Send + Sync>>
    where
        T: DatabaseEntryTrait + serde::Serialize + Clone + 'static,
        T: From<U>,
        U: serde::de::DeserializeOwned + serde::Serialize,
    {
        let WAL = Arc::clone(&self.WAL);
        let WAL = WAL.lock().await;

        // To avoid unnecessary parsing of the WAL file, we will check if it is empty.
        // I think this have to be release so to avoid passing the WAL into that function.
        drop(WAL);

        // Flush the commands to the database file to provide stateful output.
        self.flush().await?;

        // Collection could not have been created if WAL did not flush.

        let collection = self.get(collection_name).await?;
        let collection = collection.lock().await;

        // Safe to unwrap as the collection.data is always Some
        let Some(entry) = collection.data.as_ref().unwrap().get(id) else {
            return Err(format!("Entry with the provided id: {id} does not exists.").into());
        };

        return Ok(entry.as_any().downcast_ref::<T>().cloned().ok_or_else(|| {
            format!("Entry with the provided id: {id} is not of the expected type.")
        })?);
    }

    /// Select the whole collections,
    /// It would be nice to defined something like `criteria` of `HashMap<_, _>`, but since it returns generic T, we cannot easily access fields of
    /// the T that it will resolve to in the runtime, so we have to delegate that filtering of collection to the caller.
    pub async fn select_all<T, U>(
        &mut self,
        collection_name: &str,
    ) -> Result<DatabaseStorage<T>, Box<dyn Error + Send + Sync>>
    where
        T: DatabaseEntryTrait + serde::de::DeserializeOwned + serde::Serialize + Clone + 'static,
        T: From<U>,
        U: serde::de::DeserializeOwned + serde::Serialize,
    {
        let WAL = Arc::clone(&self.WAL);
        let WAL = WAL.lock().await;

        // To avoid unnecessary parsing of the WAL file, we will check if it is empty.
        // I think this have to be released so to avoid passing the WAL into that function.
        drop(WAL);

        // Flush the commands to the database file to provide stateful output.
        self.flush().await?;

        let collection = self.get(collection_name).await?;
        let collection = collection.lock().await;

        let storage = collection.cast_collection::<T>()?;

        // We do not want to use the From conversion as the data is already in DatabaseFormat,
        // and parsing it to bytes and then to concrete T would create a new instance of the type,
        // with client fields copied and database fields re-created, not existing in the database.

        return Ok(storage);
    }

    /// Contrary to `select_all`, this method returns the `DatabaseStorage<DatabaseEntry>` type,
    /// without casting to concrete T.
    pub async fn select_all_any(
        &mut self,
        collection_name: &str,
    ) -> Result<DatabaseStorage<Box<dyn DatabaseEntryTrait>>, Box<dyn Error + Send + Sync>> {
        let WAL = Arc::clone(&self.WAL);
        let WAL = WAL.lock().await;

        // To avoid unnecessary parsing of the WAL file, we will check if it is empty.
        if WAL.get_size() > 0 {
            // I think this have to be released so to avoid passing the WAL into that function.
            drop(WAL);

            // Flush the commands to the database file to provide stateful output.
            self.flush().await?;
        }

        let collection = self.get(collection_name).await?;
        let collection = collection.lock().await;

        return Ok(collection.data.as_ref().unwrap().clone());
    }

    async fn _insert(
        &mut self,
        entry: Box<dyn DatabaseEntryTrait>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // The idea of typetag is just outrageous, so stupid. We could just use the strum_macros to get the type name as string
        // and get the specific collection for given entry.

        // NOTE: Some deadlock occurs when writing the data from the WAL.

        // Retrieves the collection from the storage
        let collection = self.get(entry.typetag_name()).await?;
        let mut collection = collection.lock().await;

        let collection = collection.data.as_mut().unwrap();

        let id = entry.get_id();

        if collection.contains_key(&id) {
            return Err("Entry with the same id already exists.".into());
        }

        // Save the parsed entry to the collection
        collection.insert(id, entry);

        Ok(())
    }

    async fn _update(
        &mut self,
        entry: Box<dyn DatabaseEntryTrait>,
        id: String,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Retrieves the collection from the storage
        let collection = self.get(entry.typetag_name()).await?;
        let mut collection = collection.lock().await;

        let collection = collection.data.as_mut().unwrap();

        if !collection.contains_key(&id) {
            return Err("Entry with the provided id does not exists.".into());
        }

        // Save the parsed entry to the collection
        collection.insert(id, entry);

        Ok(())
    }

    async fn _delete(
        &mut self,
        collection_name: &str,
        id: String,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Retrieves the collection from the storage
        let collection = self.get(collection_name).await?;
        let mut collection = collection.lock().await;

        let collection = collection.data.as_mut().unwrap();

        if !collection.contains_key(&id) {
            return Err("Entry with the provided id does not exists.".into());
        }

        // Remove the entry from the collection
        collection.remove(&id);

        Ok(())
    }
}

#[derive(Debug)]
pub struct DatabaseCollection {
    /// Type of the database, used to determine which database to use when writing the data to the file system.
    // collection_name: String,
    /// File handle to the underlying storage, written when first invoked with Self::.
    handler: Arc<Mutex<File>>,
    // collection_name: ,
    /// This field is written into when we are parsing the DatabaseWAL, after that it is cleared.
    /// Technically we could keep it written into but that would waste memory, improve performance.
    ///
    /// Stays uninitialized until the WAL file is flushed.
    data: Option<DatabaseStorage<Box<dyn DatabaseEntryTrait>>>,
    // That is a clone of the WAL file, clone as the increase of the reference count, not the actual data.
    // WAL: Arc<Mutex<DatabaseWAL>>,
}

impl DatabaseCollection {
    async fn new(
        config: &DatabaseConfigEntry,
        collection_name: &str,
        // WAL: Arc<Mutex<DatabaseWAL>>,
    ) -> Result<Arc<Mutex<Self>>, Box<dyn Error + Send + Sync>> {
        Ok(Arc::new(Mutex::new(Self {
            handler: Self::open_database_file(config, &collection_name).await?,
            data: None,
        })))
    }

    /// Constructs path to database using `DatabaseEntry` enum variant which converts to string
    /// in lowercase fashion.
    ///
    /// Does not confirm the file existence.
    pub fn create_path(
        config: &DatabaseConfigEntry,
        collection_name: &str,
    ) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
        let database_root = &config.root;

        let database_path = Config::get_server_public().join(database_root);

        let mut collection_path = database_path.join(collection_name.to_string().to_lowercase());
        collection_path.set_extension("json");

        if !collection_path.starts_with(database_path) {
            info!("Collection path: {collection_path:?} is not inside the database root: ");

            return Err(Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                status_code: 400,
                status_text: "Bad Request".into(),
                message: Some("Invalid database path".to_string()),
                internals: Some(Box::<dyn Error + Send + Sync>::from(
                    "Collection path is not inside the database root.",
                )),
                content_type: Some("text/plain".to_string()),
            }));
        }

        return Ok(collection_path);
    }

    /// Creates the database file if it does not exist, and returns the file handle to it.
    /// Writes the empty JSON object to the file if it is empty.
    async fn open_database_file(
        config: &DatabaseConfigEntry,
        collection_name: &str,
    ) -> Result<Arc<Mutex<File>>, Box<dyn Error + Send + Sync>> {
        let path = Self::create_path(config, collection_name)?;

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

    async fn overwrite_database_file(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let serialized: Vec<u8> = serde_json::to_vec(&self.data)?;

        let handler = self.get_handler();
        let mut handler = handler.lock().await;

        handler.seek(std::io::SeekFrom::Start(0)).await?;
        handler.set_len(0).await?;
        handler.write_all(&serialized).await?;

        Ok(())
    }

    /// Parses the collection file to the `HashMap<String, DatabaseEntry>` type.
    async fn parse_collection(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Maybe we will use the filename as the determination of the type of the collection,

        let handler = self.get_handler();
        let mut handler = handler.lock().await;

        let mut buffer = Vec::new();

        handler.seek(std::io::SeekFrom::Start(0)).await?;
        let bytes_read = handler.read_to_end(buffer.as_mut()).await?;

        // NOTE: This should never happens as even empty file has "{}" in it.
        if bytes_read == 0 {
            return Err("Empty file".into());
        }

        // After parsing the self.data is always Some, so we can unwrap it safely.
        self.data = Some(serde_json::from_slice(&buffer)?);

        Ok(())
    }

    /// Clones the reference Arc type, increasing the reference count
    ///
    /// Unwraps the handler, if you'll delete the file during the runtime, it will panic, but that's on you.
    /// Will be fine on server restart, as the file will be recreated.
    fn get_handler(&self) -> Arc<Mutex<File>> {
        Arc::clone(&self.handler)
    }

    fn cast_collection<T>(&self) -> Result<HashMap<String, T>, Box<dyn Error + Send + Sync>>
    where
        T: DatabaseEntryTrait + serde::Serialize + Clone + 'static,
    {
        let mut serialized_data = HashMap::new();

        for (entry_id, entry) in self.data.as_ref().unwrap().iter() {
            let value = entry.as_any().downcast_ref::<T>().ok_or_else(|| {
                format!(
                    "Failed to downcast entry with id: {entry_id} to type: {}",
                    std::any::type_name::<T>()
                )
            })?;

            serialized_data.insert(entry_id.clone(), value.clone());
        }

        Ok(serialized_data)
    }
}

#[typetag::serde(tag = "__type")]
pub trait DatabaseEntryTrait: Send + Sync + Debug {
    /// Converts the entry to the `Any` trait object, so it could be downcasted to the actual type.
    fn as_any(&self) -> &dyn Any;

    fn clone_box(&self) -> Box<dyn DatabaseEntryTrait>;

    /// Returns the size of the entry in bytes. Strictly for internal use, thought I will keep it in release builds, but it will come handy.
    /// This is useful for determining the size of the entry when writing to the database and maybe to expose the size of the collection via API endpoint.
    fn get_size(&self) -> usize;

    /// Serializes the entry to the JSON format, so it could be written to the file.
    fn serialize(&self) -> Result<String, serde_json::Error>
    where
        Self: serde::Serialize + Sized,
    {
        // serde_json::to_value(self).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)
        serde_json::to_string(self)
    }

    /// Value that is used as the "primary key" for the entry. This information is could also be embedded
    /// in the entry itself. Every entry should have a unique id defined in it's struct definition.
    fn get_id(&self) -> String;

    /// Serializes the entry to bytes.
    fn as_bytes(&self) -> Result<Vec<u8>, serde_json::Error>
    where
        Self: serde::Serialize + Sized,
    {
        // Serializes the entry to the JSON format and then converts it to bytes.
        serde_json::to_vec(self)
    }

    /// Parses the bytes into concrete type which is describe in the generic parameter. Has to take the final Parsed type and Client type
    /// which is format of the data that comes from the client.
    ///
    /// We use the From trait implementation on the T to easily convert the Client type.
    /// NOTE: When From trait would end up be fallible then we would instead use TryFrom trait.
    ///
    /// We are defining this due to bad design of the WAL which requires bytes to be passed.
    /// Either way we would have to double parse even if the inserts, deletes would accepts the parsed type as it is
    /// only written to the WAL file which requires bytes being written, we could of course write the actual type as string
    /// and then parse but that is the same, either way we have to double parse the entry we are inserting.
    ///
    /// We would use that to parse specific entry in the route handler, declaring statically which type I am expecting there.
    /// That is better than defining it directly on the DatabaseEntry as if I would, I would have to match it explicitly either way,
    /// and the parsing function would be just brute-forcing the concrete type. Here it is more explicit.
    fn parse<Client>(entry: impl AsRef<[u8]>) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        Client: serde::de::DeserializeOwned + serde::Serialize,
        Self: From<Client>,
        Self: Sized,
    {
        let client = serde_json::from_slice::<Client>(entry.as_ref())?;
        return Ok(Self::from(client));
    }
}

impl Clone for Box<dyn DatabaseEntryTrait> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct DatabaseTask {
    /// Primary key.
    id: String,
    value: String,
    user_id: String,
}

impl DatabaseTask {
    pub fn get_user_id(&self) -> String {
        self.user_id.clone()
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct ClientTask {
    value: String,
    user_id: String,
}

impl ClientTask {
    /// Creates a new task with the given value and user id.
    pub fn new(value: String, user_id: String) -> Self {
        Self { value, user_id }
    }
}

#[typetag::serde(name = "Tasks")]
impl DatabaseEntryTrait for DatabaseTask {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn DatabaseEntryTrait> {
        Box::new(self.clone())
    }

    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn get_size(&self) -> usize {
        return self.value.len() + self.user_id.len() + self.id.len();
    }
}

impl From<ClientTask> for DatabaseTask {
    fn from(value: ClientTask) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            // Average expression => \(~_~)/
            value: value.value,
            user_id: value.user_id,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct DatabaseUser {
    /// Primary key.
    id: String,
    /// Arbitrary String, we won't even validate it.
    pub email: String,
    /// We could hash the password before storing it in the database, but for simplicity we will store it as plain text.
    pub password: String,
    /// User can utilize this API key to access the API. This should be created on user registration.
    API_key: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
/// User type that is return from the route handlers while creating a user. It represents the data that defines the user from the client perspective.
/// We need to do some server logic on the type, so we cannot use the `DatabaseUser` type directly as those fields are not client defined.
pub struct ClientUser {
    /// Arbitrary String, we won't even validate it.
    pub email: String,
    /// We could hash the password before storing it in the database, but for simplicity we will store it as plain text.
    pub password: String,
}

#[typetag::serde(name = "Users")]
impl DatabaseEntryTrait for DatabaseUser {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn DatabaseEntryTrait> {
        Box::new(self.clone())
    }

    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn get_size(&self) -> usize {
        // We are not hashing the password, so we can just sum the lengths of the fields.
        self.id.len() + self.email.len() + self.password.len() + self.API_key.len()
    }
}

impl DatabaseUser {
    /// Returns the API key of the user.
    pub fn get_api_key(&self) -> String {
        self.API_key.clone()
    }
}

// NOTE: If that would end up fallible we would implement `TryFrom` trait instead of `From` trait.
impl From<ClientUser> for DatabaseUser {
    fn from(value: ClientUser) -> Self {
        Self {
            API_key: uuid::Uuid::new_v4().to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            email: value.email,
            password: value.password,
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct DatabaseSession {
    id: String,
    /// User id comes form the client and is used to identify the user session.
    user_id: String,
    /// Created at is the time when the session was created.
    // pub created_at: std::time::SystemTime,
    pub expires: std::time::SystemTime,
}

impl DatabaseSession {
    pub fn duration(&self) -> Result<u64, SystemTimeError> {
        // session.expires is A SystemTime::now + 1 year, so duration since now would be just one 1 year

        self.expires
            .duration_since(std::time::SystemTime::now())
            .map(|d| d.as_secs())
    }

    pub fn get_user_id(&self) -> String {
        self.user_id.clone()
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct ClientSession {
    // Id there is of API token to allow quick lookup based on information that is already cached in the browser.
    // That is the API_key of the user.
    id: String,
    /// User id comes form the client and is used to identify the user session.
    user_id: String,
}

impl ClientSession {
    /// Since we want the session creation be server side only logic, we would define the constructor here,
    /// as the object does not come from the client, not it gets weird because we are defining the client type of the session.
    /// We also could just define the endpoint for the session creation, and delegate the task of calling that endpoint to the client.
    ///
    /// Constructor is on client type as it already have the functionality to get tagged with `typetag`, and we need that,
    /// meaning we have to construct it, parse to bytes, convert from bytes again to client type, and then to database type.
    pub fn new(id: String, user_id: String) -> Self {
        Self { id, user_id }
    }
}

#[typetag::serde(name = "Sessions")]
impl DatabaseEntryTrait for DatabaseSession {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn DatabaseEntryTrait> {
        Box::new(self.clone())
    }

    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn get_size(&self) -> usize {
        self.id.len() + self.user_id.len() + std::mem::size_of_val(&self.expires)
    }
}

impl From<ClientSession> for DatabaseSession {
    fn from(value: ClientSession) -> Self {
        Self {
            id: value.id,
            user_id: value.user_id,
            // TODO: That could be configurable, but for now we will just set it to 1 year constant.
            expires: std::time::SystemTime::now()
                + std::time::Duration::from_secs(60 * 60 * 24 * 365), // 1 year,
        }
    }
}
