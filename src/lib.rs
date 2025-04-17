mod database;
pub mod http;
pub mod logger;
pub mod prelude;

pub use http::http_request;
pub use http::http_response;

use std::error::Error;

use crate::prelude::*;

pub mod config {
    use std::collections::HashMap;
    use std::error::Error;
    use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
    use std::path::PathBuf;
    use std::sync::Arc;

    use tokio::sync::Mutex;

    use crate::database::DatabaseWAL;
    use crate::logger::Logger;

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
        /// Under development
        pub wal: Option<DatabaseWAL>,
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
            pub wal: PathBuf,
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
                    panic!(
                        "Invalid domain cause of the \":\" presence, port number should not be supplied in the domain field"
                    );
                }

                // NOTE: We will opt out of implementing deserialization for this minor transformation
                // on the data, and even if we would implement it, it would look like a
                // prefixing with server root, which is a PathBuf, converting that to String,
                // and then deserializing it back to PathBuf, which is inefficient
                // that actually applies to every transformation that we are now doing on the data

                if let Some(database) = &mut config.database {
                    database.root = Config::get_server_public().join(&database.root);
                    database.wal = Config::get_server_public().join(&database.wal);
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
                        .map(|path| {
                            Ok::<PathBuf, Box<dyn Error + Send + Sync>>(PathBuf::from(path))
                        })
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

            let wal = if let Some(database) = &config_file.database {
                Some(DatabaseWAL::new(&database).await?)
            } else {
                None
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
                wal,
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

        /// NOTE: Should be generated explicitly or used the filed set in the config file,
        ///
        pub fn get_index_path(&self) -> PathBuf {
            self.config_file.index_path.clone()
        }
    }
}

pub mod tcp_handlers {
    use super::http::HttpRequestMethod;
    use super::http_request::HttpRequest;
    use crate::config::Config::{self};
    use crate::http::{HttpHeaders, HttpResponseHeaders, HttpResponseStartLine};
    use crate::*;
    use http::HttpRequestError;
    use http_response::HttpResponse;
    use std::borrow::Cow;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    // QUESTION: Why is the server you are about to make is asynchronous, not multithreaded?
    // => FOLLOW UP QUESTION:
    //  -> Can certain tasks be handled in async manner and the other in threading manner. If any, which one should be handled in which way.
    // ANSWER: Handling multiple connection, which spawn it's separate thread is computationally heavy, may include a system call to spawn a thread,
    // otherwise in thread-pool.
    // Actually the dispute is to use async or threaded approach for handling requests
    // I will use async approach because sending a TCPStream is asynchronous task in time and the stream
    // can come at different intervals of time. Thread approach would be great if you would like to parallelize bunch of requests
    // that are independent of each other and this some sort of order of execution is not needed.

    pub async fn connect(
        config: MutexGuard<'_, Config>,
    ) -> Result<TcpListener, Box<dyn Error + Send + Sync>> {
        return TcpListener::bind(config.socket_address)
            .await
            .map_err(|e| e.into());
    }

    /// Starts TCP server with provided `Config`, continuously listens for incoming request and propagates them further.
    pub async fn run_tcp_server(
        config: Arc<Mutex<Config>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // This extra lock will only affect first load time of the server and it is also negligible
        let listener = self::connect(config.lock().await).await?;

        // println!(
        //     "TCP Connection Established at {:?}\nListening...",
        //     listener.local_addr().unwrap()
        // );

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    // println!("Connection established with: {:?}", socket);

                    let (mut reader, writer) = stream.into_split();

                    let writer = Arc::new(Mutex::new(writer));
                    let config = Arc::clone(&config);

                    let task_error_writer = Arc::clone(&writer);

                    if let Err(err) = tokio::spawn(async move {
                        let config = config.lock().await;
                        let mut writer = writer.lock().await;

                        if let Err(err) =
                            self::handle_client(&mut reader, &mut writer, &config).await
                        {
                            if let Err(err) =
                                HttpRequestError::send_error_response(&config, &mut writer, err)
                                    .await
                            {
                                eprintln!("Error sending error response: {}", err);
                            };

                            // Shutdown for writing
                            if let Err(err) = writer.shutdown().await {
                                eprintln!("Error shutting down the stream: {}", err);
                            }
                        } else {
                            // Request termination, handled successfully
                        }
                    })
                    .await
                    {
                        eprintln!("Error spawning task: {}", err);

                        let mut writer = task_error_writer.lock().await;

                        // Shut downs the writing portion of the stream if error occurs

                        if let Err(err) = writer.shutdown().await {
                            eprintln!("Error shutting down the stream: {}", err);
                        };
                    };

                    // Timeout for the request should be dependent on the method used or maybe even per path
                    // specifically for request with large payloads.
                    // if let Err(res) =
                    // tokio::time::timeout(tokio::time::Duration::from_secs(5), request_task)
                    // .await
                    // {
                    //     if let Err(err) = writer.shutdown().await {
                    //         eprintln!("Error shutting down the stream: {}", err);
                    //     }

                    // eprintln!("Request timed out: {}", res);
                    // }
                }
                Err(err) => eprintln!("Invalid TCP stream: {}", err),
            }
        }
    }

    /// Handles incoming request from the client.
    async fn handle_client(
        reader: &mut OwnedReadHalf,
        writer: &mut MutexGuard<'_, OwnedWriteHalf>,
        config: &MutexGuard<'_, Config>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let request: HttpRequest<'_> = HttpRequest::new(&config, reader).await?;
        let mut headers: HttpResponseHeaders<'_> =
            HttpResponseHeaders::new(HttpResponseStartLine::default());

        // If path is invalid and cannot be encoded, that should end the request
        let path = request.get_request_target()?;

        let (method, path) = (request.get_headers().get_method(), path);

        // println!("Requesting: {:?} {}", method, path);

        // This will be executed for every request and try to match paths that should be redirected
        // although the only redirection that we are doing is from http://127.0.0.1:<port> to http://localhost:<port>
        // paths are defined in the config file under 'domain' field, for domains and path redirect in the "paths" field

        // Give back the reference supplied to the function
        if request.redirect_request(&config, writer, &path).await? {
            return Ok(());
        };

        // Run middleware if it exists for the paths
        // path = /database/
        // middleware(request)

        // Very basic middleware to trigger some functionality on certain paths and match the pattern
        // match path {
        //     p if true => {
        //         println!("Middleware executed for path: {:?}", p.components());
        //     }
        //     _ => {}
        // }

        let body = match method {
            // This throws an error because the app is making a GET request to the path
            // that does not exists, which is correct by definition
            // NOTE: We should initialize the database only once, or at least at the top,
            // but that tomorrow...
            // GET /database/tasks.json => Database::init() => Give back the control flow to the request initialized \end_middleware
            HttpRequestMethod::GET => Some(request.read_requested_resource(&mut headers)?),
            HttpRequestMethod::POST => {
                // This would return Path not found if the path does not exists
                // If we would want to make custom endpoints without actual path existence
                // then it should be rewritten

                // NOTE: Paths under /database should validate the existence of WAL and database_config only once
                // not to avoid checking the same thing multiple times

                match path {
                    p if p == "/database/tasks.json" => {
                        if let Some(_) = config.config_file.database.as_ref() {
                            // WARNING: This code times out

                            // match request.get_body() {
                            //     Some(body) => {
                            //         let instance =
                            //             Database::<DatabaseTask>::new(&config, DatabaseType::Tasks)
                            //                 .await;

                            //         instance.insert(body).await;
                            //     }
                            //     None => {}
                            // }
                        } else {
                            panic!("DROP DATABASE \"\\ROOT\" EXECUTED SUCCESSFUL");
                        }

                        return Err(
                            "Database insertions are not implemented yet, as the whole database",
                        )?;
                    }
                    _ => {
                        eprintln!("Path does not exists on the server or the method used is unsupported for that path: {:?}", path);

                        return Err(HttpRequestError {
                            status_code: 404,
                            status_text: String::from("Not Found"),
                            message: String::from("Path does not exists on the server or the method used is unsupported for that path").into(),
                            content_type: "text/plain".to_string().into()
                        })?;
                    }
                }
            }
            HttpRequestMethod::DELETE => todo!(),
            HttpRequestMethod::UPDATE => todo!(),
            HttpRequestMethod::PUT => todo!(),
        };

        headers.add(Cow::from("Connection"), Cow::from("close"));

        let mut response: HttpResponse<'_> = HttpResponse::new(headers, body);

        response.write(&config, writer).await?;
        Ok(())
    }
}
