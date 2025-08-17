use std::{any::Any, time::SystemTimeError};

use horrible_database::DatabaseEntryTrait;

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
