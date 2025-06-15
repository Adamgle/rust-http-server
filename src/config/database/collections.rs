use serde_json;
use std::any::Any;
use std::error::Error;
use std::fmt::Debug;

use crate::config::database::DatabaseType;

pub trait DatabaseEntryTrait: Send + Sync + Debug + Any {
    /// Converts the entry to the `Any` trait object, so it could be downcasted to the actual type.
    fn as_any(&self) -> &dyn Any;

    /// Serializes the entry to the JSON format, so it could be written to the file.
    fn serialize(&self) -> serde_json::Value;

    /// Value that is used as the "primary key" for the entry. This information is could also be embedded
    /// in the entry itself. Every entry should have a unique id defined in it's struct definition.
    fn get_id(&self) -> String;
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct DatabaseTask {
    id: String,
    /// Primary key.
    value: String,
}

impl DatabaseEntryTrait for DatabaseTask {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn serialize(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    fn get_id(&self) -> String {
        self.id.clone()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct DatabaseUser {
    /// Primary key.
    id: String,
    /// Arbitrary String, we won't even validate it.
    email: String,
    /// We could hash the password before storing it in the database, but for simplicity we will store it as plain text.
    password: String,
    /// User can utilize this API key to access the API. This should be created on user registration.
    API_key: String,
}

// #[typetag::serde]
impl DatabaseEntryTrait for DatabaseUser {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn serialize(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    fn get_id(&self) -> String {
        self.id.clone()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct DatabaseEntry(Vec<u8>);

impl DatabaseEntry {
    pub fn new(bytes: &impl AsRef<[u8]>) -> Self {
        DatabaseEntry(bytes.as_ref().to_vec())
    }

    /// Main deserializer function for the `DatabaseEntry` struct.
    ///
    /// Deserializes the entry to the actually type behind the trait object of `DatabaseEntryTrait` defined with `Box<dyn DatabaseEntryTrait>`.
    ///
    /// `NOTE`: This function is `STATIC` and would require change in definition if new `DatabaseType` would be added.
    pub fn parse(
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
