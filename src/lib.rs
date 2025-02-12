mod database;
mod http;
mod http_request;
mod http_response;
pub mod logger;
pub mod prelude;

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
        pub server_root: PathBuf,
        pub socket_address: SocketAddrV4,
        pub options: Option<HashMap<String, String>>,
        pub http_host: url::Url,
        // NOTE: It's not optional because in the near future we will create the file with default when the server starts
        pub config_file: config_file::ServerConfigFile,
        pub logger: Logger,
        pub wal: Option<DatabaseWAL>,
    }

    // TODO: Config file should be generate when server is first started with some crap that is default and required
    // for server to work, like `protocol` field.
    pub mod config_file {
        use super::Config;
        use std::{fs, path::PathBuf};

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
        }

        impl ServerConfigFile {
            pub fn get_config() -> Result<ServerConfigFile, Box<dyn std::error::Error>> {
                // suffix paths relative to the root
                let config_path = Config::get_server_root().join("config/config.json");

                // Deserialize the config file
                let mut config =
                    serde_json::from_str::<ServerConfigFile>(&fs::read_to_string(config_path)?)?;

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
        pub async fn new(args: Vec<String>) -> Result<Arc<Mutex<Config>>, Box<dyn Error>> {
            if args.len() < 2 {
                return Err(format!("Usage: {} <address:port> [server_root_path]", args[0]).into());
            }

            // Required instead of parsing to SocketAddrV4 because we could not supply `localhost` as a socket
            // because parsing would fail
            let socket_address = match args[1].to_socket_addrs()?.find(|addr| addr.is_ipv4()) {
                Some(SocketAddr::V4(addr)) => addr,
                _ => return Err("Invalid IPv4 socket address".into()),
            };

            let options = Config::parse_options(args.get(2));

            // Check if SERVER_ROOT env specified, if not check command line argument, if not use default
            // as `{working_dir}/public`
            let server_root = match std::env::var("SERVER_ROOT") {
                Ok(server_root) => PathBuf::from(server_root),
                Err(_) => args
                    .get(3)
                    .map(|path| Ok::<PathBuf, Box<dyn Error>>(PathBuf::from(path)))
                    .unwrap_or_else(|| {
                        // Default path
                        let default_path = std::env::current_dir()?;
                        println!("Using: {:?} as server_root", default_path);
                        Ok(default_path)
                    })?,
            };

            // In all the above did not throw and error, we will set the environment variables
            // Set the SERVER_ROOT, SERVER_PUBLIC, SERVER_PORT environment variables
            // refer as std::env::var("SERVER_ROOT") to get the value
            std::env::set_var("SERVER_ROOT", &server_root);
            std::env::set_var("SERVER_PUBLIC", &server_root.join("public"));
            std::env::set_var("SERVER_PORT", socket_address.port().to_string());

            // This has to be done AFTER env's are set, as it may rely on them
            let config_file = config_file::ServerConfigFile::get_config()?;

            let wal = if let Some(database) = &config_file.database {
                Some(DatabaseWAL::new(&database).await?)
            } else {
                None
            };

            Ok(Arc::new(Mutex::new(Config {
                socket_address,
                options,
                server_root,
                config_file,
                // database_wal,
                // This will normalize localhost and 127.0.0.1 in URL
                http_host: url::Url::parse(&format!("http://{}", socket_address))?,
                logger: Logger {},
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

        pub fn get_index_path(&self) -> PathBuf {
            self.config_file.index_path.clone()
        }
    }
}

pub mod tcp_handlers {
    use super::http::{HttpHeaders, HttpProtocol, HttpRequestMethod};
    use super::http_request::HttpRequest;
    use crate::config::Config::{self};
    use crate::database::{Database, DatabaseCommand, DatabaseTask, DatabaseType};
    use crate::*;
    use http::{HttpRequestError, HttpResponseStartLine};
    use http_response::HttpResponse;
    use std::borrow::Cow;
    use std::path::Path;
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Mutex;

    // QUESTION: Why there server you are about to make is asynchronous, not multithreaded?
    // => FOLLOW UP QUESTION:
    //  -> Can certain tasks be handled in async manner and the other in threading manner. If any, which one should be handled in which way.
    // ANSWER: Handling multiple connection, which spawn it's separate thread is computationally heavy, may include a system call to spawn a thread,
    // otherwise in thread-pool.
    // Actually the dispute is to use async or threaded approach for handling requests
    // I will use async approach because sending a TCPStream is asynchronous task in time and the stream
    // can come at different intervals of time. Thread approach would be great if you would like to parallelize bunch of requests
    // that are independent of each other and this some sort of order of execution is not needed.

    pub async fn connect(config: MutexGuard<'_, Config>) -> Result<TcpListener, Box<dyn Error>> {
        return TcpListener::bind(config.socket_address)
            .await
            .map_err(|e| e.into());
    }

    /// NOTE: Can log anything that implements `std::fmt::Display`
    ///
    /// Logs request or response that come from the client or response from the server to ./log.txt

    /// Sends error response to the client, based on the error that occurred during request handling
    /// downcasting to the specific error type from `Box<dyn Error>` and handling it accordingly
    ///
    /// If stream is None,
    /// If err is None, send default 500 Internal Server Error response
    async fn send_error_response(
        config: Arc<Mutex<Config>>,
        stream: &mut TcpStream,
        // http_err: Option<&HttpRequestError>,
        mut err: Option<Box<dyn Error>>,
    ) -> Result<(), Box<dyn Error>> {
        let config = config.lock().await;

        let pages_path = std::path::Path::new("public/pages/");

        // If err is None, send default 500 Internal Server Error response
        if err.is_none() {
            err = Some(HttpRequestError::default().into())
        }

        if let Some(err) = err {
            if let Some(http_err) = err.downcast_ref::<HttpRequestError>() {
                let start_line = HttpResponseStartLine::new(
                    HttpProtocol::HTTP1_1,
                    http_err.status_code,
                    &http_err.status_text,
                )
                .into();

                let mut response_headers = HttpResponse::new_headers(start_line);

                // Setting default content-type as text/html
                response_headers.add(
                    Cow::from("Content-Type"),
                    Cow::from(
                        http_err
                            .content_type
                            .clone()
                            .unwrap_or(String::from("text/html")),
                    ),
                );

                let body = match &http_err.content_type {
                    Some(content_type) if content_type == "application/json" => {
                        serde_json::to_string(http_err)?
                    }
                    Some(content_type) if content_type == "text/plain" => {
                        format!("{:#?}", http_err)
                    }
                    // NOTE: matching different content-types
                    // Some(content_type) if content_type == "application/x-www-form-urlencoded"
                    _ => std::fs::read_to_string(pages_path.join("error.html"))?,
                };

                response_headers.add(
                    Cow::from("Content-Length"),
                    Cow::from(body.len().to_string()),
                );

                let mut response = HttpResponse::new(response_headers, Some(body))?;
                return response.write(&config, stream).await;
            } else {
                // Sending text/plain as the error message if the error is not of the HttpRequestError type

                let mut headers = HttpResponse::new_headers(
                    HttpResponseStartLine::new(HttpProtocol::HTTP1_1, 500, "Internal Server Error")
                        .into(),
                );

                headers.add(Cow::from("Content-Type"), Cow::from("text/plain"));

                // NOTE: This should not happen, error could contain internal server error messages
                // thereby exposing sensitive information to the client
                let body = format!(
                    "An error occurred while processing a request:\nWith error: {:#?}",
                    err
                );

                headers.add(
                    Cow::from("Content-Length"),
                    Cow::from(body.len().to_string()),
                );

                let mut response = HttpResponse::new(headers, Some(body))?;

                return response.write(&config, stream).await;
            }
            // NOTE: This is how you can handle different errors by downcasting to the specific error type
            // else if let Some(io_err) = err.downcast_ref::<std::io::Error>() {}
        } // You could propagate anything to the client there, for example for dev purposes:
          // NOTE: It propagates full error message to the client

        Ok(())
    }

    /// Starts TCP server with provided `Config`, continuously listens for incoming request and propagates them further.
    pub async fn run_tcp_server(config: Arc<Mutex<Config>>) -> Result<(), Box<dyn Error>> {
        // This extra lock will only affect first load time of the server and it is also negligible
        let listener = self::connect(config.lock().await).await?;

        println!(
            "TCP Connection Established at {:?}\nListening...",
            listener.local_addr().unwrap()
        );

        loop {
            // for stream in listener.incoming() {
            match listener.accept().await {
                Ok((mut stream, socket)) => {
                    println!("Connection established with: {:?}", socket);

                    // NOTE: This is very bad, if we would design it to hold database because of the inefficiencies
                    // while writing to it a new entry, that also copy the whole database to the memory
                    // let mut config_clone = config.clone();

                    // Mem inspect config
                    // println!("Size the Config struct that is being copied in every single request because it spawns it's separate async task {:#?}",
                    // std::mem::size_of_val(&config_clone));

                    let config = Arc::clone(&config);

                    if let Err(res) = tokio::time::timeout(
                        tokio::time::Duration::from_secs(5),
                        tokio::spawn(async move {
                            // let config = config.lock().await;
                            // let mut config = Arc::new(Mutex::new(config));
                            // let mut config = config.lock().await;

                            let config = config.lock().await;

                            if let Err(err) = self::handle_client(&mut stream, config).await {
                                eprintln!("Error handling request: {}", err);
                                // send_error_response(&mut config_clone, &mut stream, Some(err)).await?;
                            } else {
                                // Request termination
                                // println!("Request handled successfully")
                            }
                        }),
                    )
                    .await
                    {
                        eprintln!("Request timed out: {}", res);
                    }
                }
                Err(err) => eprintln!("Invalid TCP stream: {}", err),
            }
        }
    }

    /// Handles incoming request from the client.
    async fn handle_client(
        stream: &mut TcpStream,
        config: MutexGuard<'_, Config>,
    ) -> Result<(), Box<dyn Error>> {
        let request: HttpRequest<'_> = HttpRequest::new(&config, stream).await?;

        let mut response_headers: HttpHeaders<'_> = HttpResponse::new_headers(None);

        let (method, path) = (
            request.get_method(),
            request.get_path_segment(&config).await?,
        );

        println!("Requesting: {:?} {}", method, path.display());

        // This will be executed for every request and try to match paths that should be redirected
        // although the only redirection that we are doing is from http://127.0.0.1:<port> to http://localhost:<port>
        // paths are defined in the config file under 'domain' field, for domains and path redirect in the "paths" field

        // Give back the reference supplied to the function
        if request.redirect_request(stream, &config).await? {
            return Ok(());
        };

        let response_body = match method {
            // This throws an error because the app is making a GET request to the path
            // that does not exists, which is correct by definition
            // NOTE: We should initialize the database only once, or at least at the top,
            // but that tomorrow...
            HttpRequestMethod::GET => Some(request.read_requested_resource(&mut response_headers)?),
            HttpRequestMethod::POST => {
                // This would return Path not found if the path does not exists
                // If we would want to make custom endpoints without actual path existence
                // then it should be rewritten

                // let resource = request.get_absolute_resource_path()?;

                // NOTE: Paths under /database should validate the existence of wal and database_config only once
                // not to avoid checking the same thing multiple times
                match path {
                    p if p == Path::new("database/tasks.json") => {
                        // if let Some(database_config) = config.config_file.database.as_ref() {
                        match request.get_body() {
                            Some(body) => {
                                let instance =
                                    Database::<DatabaseTask>::new(&config, DatabaseType::Tasks)
                                        .await;

                                instance.insert(body).await;
                            }
                            None => {}
                        }
                        // }
                        unimplemented!()

                        // unimplemented!()
                        // } else {
                        // panic!("DROP DATABASE \"\\ROOT\" EXECUTED SUCCESSFUL");
                        // }
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

        response_headers.add(Cow::from("Connection"), Cow::from("close"));

        let mut response: HttpResponse<'_> = HttpResponse::new(response_headers, response_body)?;

        response.write(&config, stream).await?;
        Ok(())
    }
}
