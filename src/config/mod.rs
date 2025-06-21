pub mod database;

use crate::http::HttpRequestMethod;
use crate::logger::Logger;
use crate::routes::{RouteTable, RouteTableKey};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ffi::OsStr;
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use strum::IntoEnumIterator;
use tokio::sync::Mutex;

use self::database::Database;

#[derive(Debug)]
/// `NOTE`: It would be good idea to document that
/// 'a is the lifetime of the RouteTable, 'b is the lifetime of the context given to the callback
/// of the handler, RouteHandlerContext<'b>.
pub struct Config {
    pub socket_address: SocketAddrV4,
    /// `unimplemented!()`
    pub options: Option<HashMap<String, String>>,
    pub app: AppConfig,
    /// `NOTE`: It's not optional because in the near future we will create the file with default when the server starts
    pub config_file: config_file::ServerConfigFile,
    /// `unimplemented!()`
    pub logger: Logger,
    pub database: Option<Arc<Mutex<Database>>>,
}

/// Contains information related to the application configuration, not the server configuration.
///
/// It is used to store the URL of the server, routes, and other application-specific settings.
pub struct AppConfig {
    /// URL of the server, composed of the parts in the config file, under `protocol` and `domain`, with `port` number
    /// set on the `SERVER_PORT` environment variable.
    pub url: url::Url,
    /// `routes` is a HashMap of routes, where key is a tuple of path and method,
    /// and value is a function that takes a mutable reference to HttpRequest and HttpResponseHeaders.
    /// We are evaluating the routes on startup and use it for the duration of the program.
    pub routes: RouteTable,
}

impl AppConfig {
    /// Creates a new AppConfig
    // pub fn new(url: url::Url) -> Result<Self, Box<dyn Error + Send + Sync>> {
    //     Ok(AppConfig {
    //         routes: Self::create_routes()?,
    //         url,
    //     })
    // }

    /// Creates a new routes HashMap, that is used to store the routes of the application.
    /// Routes are defined statically in the code, and are evaluated on startup.
    ///
    /// Since the function could get big, we will use a wrapper function to create the routes.
    pub fn create_routes() -> Result<RouteTable, Box<dyn Error + Send + Sync>> {
        crate::routes::RouteTable::create_routes()
    }
}

// We will omit value of the routes HashMap to be printed as it is a function pointer
impl std::fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig")
            .field("url", &self.url)
            .field("routes", &self.routes)
            // .field("routes", &self.routes.0.keys().collect::<Vec<_>>())
            .finish()
    }
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
    #[allow(non_snake_case)]
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
        /// `TODO`: That should be renamed to `host` as that is host not domain, and any other fields using
        /// word `domain` should be renamed to `host` as well
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
        pub fn domain_to_url(&self, domain: &str, port: &u16) -> Result<url::Url, url::ParseError> {
            Ok(url::Url::parse(&format!(
                "{}://{}:{}",
                self.protocol, domain, port
            ))?)
        }
    }
}

#[derive(strum_macros::Display, strum_macros::EnumIter)]
#[strum(serialize_all = "lowercase")]
/// If resource is requested, it will try to find it in the `public` directory
pub enum SpecialDirectories {
    /// under `pages`, `{public}/pages`.
    /// First, if the path contains `.html` extension it will look it up in the `pages` directory,
    /// Second, if the path is requested without an extension, it will assume that directory is requested
    /// and look it up in the `pages` directory, suffixing with `index.html`
    /// Third, If none of the above is true, it will thrown an error.
    Pages,
    /// Directory related to static styles, any with `.css` extension will be looked up in that directory
    /// under `public` directory.
    Styles,
    /// Directory related to static scripts, any with `.js` extension will be looked up in that directory.
    /// under `public` directory.
    Client,
    /// No restriction for authentication and type of the files stored.
    Assets,
    // ServerRoot, => We won't support this there as they are dynamic, defined base on information in the config files
    // ServerPublic, => We won't support this there as they are dynamic, defined base on information in the config file
    // ServerConfig, => We won't support this there as they are dynamic, defined base on information in the config file
}

impl SpecialDirectories {
    /// Returns the path to the directory under `SERVER_PUBLIC` environment variable
    pub fn get_path(&self) -> PathBuf {
        let public = Config::get_server_public();

        return public.join(self.to_string().to_lowercase());
    }

    /// Recursively walks through the directories and collects all files in the directory,
    /// stripping the prefix of the `SERVER_PUBLIC` directory.
    fn walk_dir(
        path: &impl AsRef<Path>,
        paths: &mut HashSet<RouteTableKey>,
        prefix: &PathBuf,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Ok(entries) = std::fs::read_dir(path.as_ref()) {
            for entry in entries.flatten() {
                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    // If the entry is a directory, recursively walk through it
                    let sub_path = entry.path();
                    Self::walk_dir(&sub_path, paths, prefix)?;
                } else if file_type.is_file() {
                    // If the entry is a file, add it to the set of paths

                    let file_path = entry.path();
                    // println!("file_path: {:?} | prefix: {:?}", file_path, prefix);

                    let file_path = file_path.strip_prefix(prefix).inspect_err(|e| {
                        eprintln!("File not under public directory: {:?}", e);
                    })?;

                    // Replace windows separator "\\" with unix separator "/"
                    // Non-UTF-8 paths are skipped because they are unsupported.
                    let file_path = file_path.to_str().map(|s| s.replace('\\', "/").to_string());

                    // println!("Path collected: {:?}", file_path);

                    // Insert the file path into the set, converting it to PathBuf
                    // Every path can be accessed with GET method, nothing else is guaranteed.
                    if let Some(file_path) = file_path {
                        // We are using PathBuf to store the path, and HttpRequestMethod::GET as the method
                        // that can be used to access the file.

                        paths.insert(RouteTableKey::new(
                            PathBuf::from(file_path),
                            Some(HttpRequestMethod::GET),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// This functions Vector of paths, relative to the `SERVER_PUBLIC` directory,
    /// that are available for the user to request.
    ///
    /// Any file under SpecialDirectories can be requested by the user with authentication,
    /// with a GET method.
    ///
    /// NOTE: Normally that kind of functionality would be statically generated at build time, and it is in routes table.
    pub fn collect() -> Result<HashSet<RouteTableKey>, Box<dyn Error + Send + Sync>> {
        // We should walk through the directories and collect all files,

        let mut paths = HashSet::<RouteTableKey>::new();
        let public = Config::get_server_public();

        for dir in SpecialDirectories::iter() {
            let path = dir.get_path();
            Self::walk_dir(&path, &mut paths, &public)
                .inspect_err(|e| eprintln!("Error walking through directory {:?}: {}", path, e))?;
        }

        return Ok(paths);
    }

    pub fn resolve_path(ext: &OsStr) -> Option<String> {
        ext.to_str().and_then(|ext| match ext {
            "html" => Some(Self::Pages.to_string()),
            "css" => Some(Self::Styles.to_string()),
            "js" => Some(Self::Client.to_string()),
            _ => None,
        })
    }
}

impl Config {
    /// Parses user defined args while executing the program
    pub async fn new(args: Vec<String>) -> Result<Arc<Mutex<Self>>, Box<dyn Error + Send + Sync>> {
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

        // If database is configured in the config file, it would initialized on server startup.
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

        let app_config = AppConfig {
            url: config_file
                .domain_to_url(&domain, &socket_address.port())
                .inspect_err(|e| eprintln!("Error parsing domain to URL: {}", e))?,
            routes: AppConfig::create_routes()?,
        };

        Ok(Arc::new(Mutex::new(Config {
            socket_address,
            options,
            // server_root,
            config_file,
            logger: Logger {},
            app: app_config,
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

    /// Check if the database is initialized and return a clone of the Arc<Mutex<Database>> if it is.
    pub fn get_database(&self) -> Result<Arc<Mutex<Database>>, Box<dyn Error + Send + Sync>> {
        // Database config already checked in the Config constructor, no need to check it again.
        if let Some(_) = &self.config_file.database {
            if let Some(database) = &self.database {
                // If database is initialized, return a clone of the Arc<Mutex<Database>>
                return Ok(Arc::clone(database));
            }
        }

        return Err("Database not initialized".into());
    }

    pub fn get_routes(&self) -> &RouteTable {
        &self.app.routes
    }

    pub fn get_routes_mut(&mut self) -> &mut RouteTable {
        &mut self.app.routes
    }
}
