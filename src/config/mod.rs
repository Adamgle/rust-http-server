pub mod database;

use crate::logger::Logger;
use std::collections::HashMap;
use std::error::Error;
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use self::database::Database;

#[derive(Debug)]
/// `NOTE`: It would be good idea to document that
pub struct Config {
    pub socket_address: SocketAddrV4,
    /// `unimplemented!()`
    pub options: Option<HashMap<String, String>>,
    /// URL of the server, composed of the parts in the config file, under `protocol` and `domain`, with `port` number
    /// set on the `SERVER_PORT` env
    pub http_url: url::Url,
    /// `NOTE`: It's not optional because in the near future we will create the file with default when the server starts
    pub config_file: config_file::ServerConfigFile,
    /// `unimplemented!()`
    pub logger: Logger,
    /// Under development,
    /// `NOTE`: I think that should be removed from there, kind of shenanigans.
    /// `NOTE`: Waiting to be fixed        
    // #[allow(dead_code)]
    pub database: Option<Arc<Mutex<Database>>>,
}

// TODO: Config file should be generate when server is first started with some crap that is default and required
// for server to work, like `protocol` field.
pub mod config_file {
    use super::Config;
    use std::{error::Error, fs, path::PathBuf};

    #[derive(Debug, Clone)]
    pub enum ConfigHttpProtocol {
        HTTP,
        HTTPS,
    }

    // case insensitive deserialization of the protocol field
    impl<'de> serde::Deserialize<'de> for ConfigHttpProtocol {
        fn deserialize<D>(deserializer: D) -> Result<ConfigHttpProtocol, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            match s.to_lowercase().as_str() {
                "http" => Ok(ConfigHttpProtocol::HTTP),
                "https" => Ok(ConfigHttpProtocol::HTTPS),
                _ => Err(serde::de::Error::custom("Invalid protocol")),
            }
        }
    }

    impl std::fmt::Display for ConfigHttpProtocol {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ConfigHttpProtocol::HTTP => write!(f, "http"),
                ConfigHttpProtocol::HTTPS => write!(f, "https"),
            }
        }
    }

    #[derive(serde::Deserialize, Debug, Clone)]
    pub struct RedirectPathsEntry {
        pub from: url::Url,
        pub to: url::Url,
    }

    // Alias for RedirectPathsEntry, basically the same structure
    #[derive(serde::Deserialize, Debug, Clone)]
    pub struct RedirectDomainsEntry {
        pub from: String,
        pub to: String,
    }

    #[derive(serde::Deserialize, Debug, Clone)]
    pub struct RedirectEntry {
        pub domains: Option<Vec<RedirectDomainsEntry>>,
        pub paths: Option<Vec<RedirectPathsEntry>>,
    }

    // `index_path` and `protocol` are not optional because they are required for server to work
    // and they will be set to defaults if not supplied
    #[derive(serde::Deserialize, Debug, Clone)]
    pub struct DatabaseConfigEntry {
        /// `root` directory where paths are defined, relative to the server `/public`
        pub root: PathBuf,
        /// `wal` file path of write-ahead log, relative to the server `/public`
        pub WAL: PathBuf,
    }

    #[derive(serde::Deserialize, Debug, Clone)]
    pub struct ServerConfigFile {
        pub index_path: PathBuf,
        // This probably should not be public and maybe the database should not even be in the /public dir
        pub database: Option<DatabaseConfigEntry>,
        pub redirect: Option<RedirectEntry>,
        pub protocol: ConfigHttpProtocol,
        pub domain: String,
    }

    impl ServerConfigFile {
        pub fn get_config() -> Result<ServerConfigFile, Box<dyn Error + Send + Sync>> {
            // suffix paths relative to the root
            let config_path = Config::get_server_root().join("config/config.json");

            // Deserialize the config file
            let mut config =
                serde_json::from_str::<ServerConfigFile>(&fs::read_to_string(config_path)?)?;

            if config.domain.contains(":") {
                return Err(
                        "Invalid domain cause of the \":\" presence, port number should not be supplied in the domain field".into()
                    );
            }

            // NOTE: We will opt out of implementing deserialization for this minor transformation
            // on the data, and even if we would implement it, it would look like a
            // prefixing with server root, which is a PathBuf, converting that to String,
            // and then deserializing it back to PathBuf, which is inefficient
            // that actually applies to every transformation that we are now doing on the data

            if let Some(database) = &mut config.database {
                database.root = Config::get_server_public().join(&database.root);
                database.WAL = Config::get_server_public().join(&database.WAL);
            }

            // NOTE: This should be done by implementing the Iterator trait on the field
            // but I do not care about this field as it also should be rewritten and this suffix_domain_with_port
            // should never happen, separate field should be created for that

            // Map the domains with port number if specified
            if let Some(redirect) = config.redirect.as_mut() {
                if let Some(domains) = redirect.domains.as_mut() {
                    for domain in domains {
                        // NOTE: That allowance of port number in domain could change in the future

                        // Port number in http URL is right after the domain name
                        // so we could check for the presence of  `:` to check if port is supplied

                        // NOTE: This should probably create different key-value in that config
                        // because this is not a valid domain given that transformation
                        domain.from = ServerConfigFile::suffix_domain_with_port(&domain.from);
                        domain.to = ServerConfigFile::suffix_domain_with_port(&domain.to);
                    }
                }
            }

            Ok(config)
        }

        fn suffix_domain_with_port(domain: &str) -> String {
            // Check if domain is supplied with port number
            if domain.contains(":") {
                // If not supplied, suffix with the SERVER_PORT
                domain.to_string()
            } else {
                format!("{}:{}", domain, Config::get_server_port())
            }
        }

        // NOTE: Work around, make domains practically invalids domain just to fit the requirement for the application
        // new field specific for that functionality should be created
        pub fn domain_to_url(&self, domain: &str) -> Result<url::Url, url::ParseError> {
            Ok(url::Url::parse(&format!("{}://{}", self.protocol, domain))?)
        }
    }
}

impl Config {
    /// Parses user defined args while executing the program
    pub async fn new(
        args: Vec<String>,
    ) -> Result<Arc<Mutex<Config>>, Box<dyn Error + Send + Sync>> {
        if args.len() < 2 {
            return Err(format!("Usage: {} <address:port> [server_root_path]", args[0]).into());
        }

        // Required instead of parsing to SocketAddrV4 because we could not supply `localhost` as a socket
        // because parsing would fail
        // Resolves localhost to 127.0.0.1
        let socket_address = match args[1].to_socket_addrs()?.find(|addr| addr.is_ipv4()) {
            Some(SocketAddr::V4(addr)) => addr,
            _ => return Err("Invalid IPv4 socket address".into()),
        };

        let options = Config::parse_options(args.get(2));

        // Check if SERVER_ROOT env specified, if not check command line argument, if not use default
        // as `{working_dir}`
        let server_root = match std::env::var("SERVER_ROOT") {
            Ok(server_root) => PathBuf::from(server_root),
            Err(_) => {
                let root = args
                    .get(3)
                    .map(|path| Ok::<PathBuf, Box<dyn Error + Send + Sync>>(PathBuf::from(path)))
                    .unwrap_or_else(|| {
                        let default_path = std::env::current_dir()?;
                        println!("Using: {:?} as server_root", default_path);

                        Ok(default_path)
                    })?;

                std::env::set_var("SERVER_ROOT", &root);
                root
            }
        };

        // In all the above did not throw and error, we will set the environment variables
        // Set the SERVER_ROOT, SERVER_PUBLIC, SERVER_PORT environment variables
        // refer as std::env::var("SERVER_ROOT") to get the value
        // technically we could check if not they exists, thought that is unnecessary

        std::env::set_var("SERVER_PUBLIC", &server_root.join("public"));
        std::env::set_var("SERVER_PORT", socket_address.port().to_string());

        // This has to be done AFTER env's are set, as it may rely on them
        let config_file = config_file::ServerConfigFile::get_config()?;

        let database = match config_file.database.as_ref() {
            Some(database_config) => Some(Arc::new(Mutex::new(
                Database::new(database_config).await.inspect_err(|e| {
                    eprintln!("Error initializing database: {}", e);
                })?,
            ))),
            None => {
                println!("Database not configured in the config file under /database branch.");
                None
            }
        };

        let domain = config_file.domain.clone();

        // As the url::Url does not allow relative url parsing, we are initializing one to default url,
        // though only the path segment is the important part

        // Bat-shit crazy
        let http_url = url::Url::parse(&format!(
            "{}://{}:{}",
            config_file.protocol,
            domain,
            socket_address.port().to_string()
        ))?;

        Ok(Arc::new(Mutex::new(Config {
            socket_address,
            options,
            // server_root,
            config_file,
            logger: Logger {},
            http_url,
            database,
        })))
    }

    pub fn parse_options(options: Option<&String>) -> Option<HashMap<String, String>> {
        match options {
            // TODO: TBD
            Some(_data) => return Some(HashMap::<String, String>::new()),
            None => None,
        }
    }

    /// This function does not operator on the Config instance, path is returned from
    /// environment variables
    ///
    /// NOTE: We are assuming env always exists, if not the error would be thrown earlier, so it is safe to unwrap.
    /// Cannot be used internally in Config methods because that could panic when env is not set
    pub fn get_server_public() -> PathBuf {
        // Also we are assuming that the actual path exists, because of the call to canonicalize.
        PathBuf::from(std::env::var("SERVER_PUBLIC").expect("SERVER_PUBLIC env not set"))
            .canonicalize()
            .expect("Server public path set in the SERVER_PUBLIC env does not exists")
    }

    /// Natively return current working directory.
    ///
    /// NOTE: This function does not operator on the Config instance, path is returned from environment variables
    ///
    /// NOTE: We are assuming env always exists, if not the error would be thrown earlier, so it is safe to unwrap.
    /// Cannot be used internally in Config methods because that could panic when env is not set
    pub fn get_server_root() -> PathBuf {
        PathBuf::from(std::env::var("SERVER_ROOT").expect("SERVER_ROOT env not set"))
            .canonicalize()
            .expect("Server root path set in the SERVER_ROOT env does not exists")
    }

    pub fn get_server_port() -> String {
        std::env::var("SERVER_PORT").expect("server_port not set in the SERVER_PORT env")
    }

    pub fn get_index_path(&self) -> PathBuf {
        self.config_file.index_path.clone()
    }

    pub fn get_database_config(&self) -> Option<&config_file::DatabaseConfigEntry> {
        self.config_file.database.as_ref()
    }

    /// `NOTE`: Dummy types in return statement
    pub fn get_database(&self) -> Result<Arc<Mutex<Database>>, Box<dyn Error + Send + Sync>> {
        if let Some(database) = &self.database {
            Ok(Arc::clone(database))
        } else {
            Err("Database not initialized".into())
        }
    }
}
