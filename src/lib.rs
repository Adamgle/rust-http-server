mod http;
mod http_request;
mod http_response;
mod logger;

use std::error::Error;
use std::net::{TcpListener, TcpStream};

pub mod database {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    pub struct DatabaseEntry {
        pub value: String,
        pub id: u32,
    }
}

pub mod config {
    use std::collections::HashMap;
    use std::error::Error;
    use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
    use std::path::PathBuf;

    #[derive(Debug)]
    pub struct Config {
        pub server_root: PathBuf,
        pub socket_address: SocketAddrV4,
        pub options: Option<HashMap<String, String>>,
        pub http_host: url::Url,
        // NOTE: It's not optional because in the near future we will create the file with default when the server starts
        pub config_file: config_file::ServerConfigFile,
        // pub logger: Logger,
    }

    // TODO: Config file should be generate when server is first started with some crap that is default and required
    // for server to work, like `protocol` field.
    pub mod config_file {
        use serde::Deserialize;

        use super::Config;
        use std::{fs, path::PathBuf};

        #[derive(serde::Serialize, Debug)]
        pub enum ConfigHttpProtocol {
            HTTP,
            HTTPS,
        }

        // impl for deserialization to lowercase of the protocol field
        impl<'de> Deserialize<'de> for ConfigHttpProtocol {
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

        #[derive(serde::Deserialize, serde::Serialize, Debug)]
        pub struct RedirectPathsEntry {
            pub from: url::Url,
            pub to: url::Url,
        }

        // Alias for RedirectPathsEntry, basically the same structure
        #[derive(serde::Deserialize, serde::Serialize, Debug)]
        pub struct RedirectDomainsEntry {
            pub from: String,
            pub to: String,
        }

        #[derive(serde::Deserialize, serde::Serialize, Debug)]
        pub struct RedirectEntry {
            pub domains: Option<Vec<RedirectDomainsEntry>>,
            pub paths: Option<Vec<RedirectPathsEntry>>,
        }

        #[derive(serde::Deserialize, serde::Serialize, Debug)]
        // `index_path` and `protocol` are not optional because they are required for server to work
        // and they will be set to defaults if not supplied
        pub struct ServerConfigFile {
            pub index_path: PathBuf,
            pub redirect: Option<RedirectEntry>,
            pub protocol: ConfigHttpProtocol,
        }

        impl ServerConfigFile {
            pub fn get_config() -> Result<ServerConfigFile, Box<dyn std::error::Error>> {
                let config_path = Config::get_server_root().join("config/config.json");
                let mut config =
                    serde_json::from_str::<ServerConfigFile>(&fs::read_to_string(config_path)?)?;

                // Map the domains with port number if specified
                if let Some(redirect) = config.redirect.as_mut() {
                    if let Some(domains) = redirect.domains.as_mut() {
                        for domain in domains {
                            // NOTE: That allowance of port number in domain could change in the future

                            // Port number in http URL is right after the domain name
                            // so we could check for the presence of  `:` to check if port is supplied

                            domain.from = ServerConfigFile::suffix_domain_with_port(&domain.to);
                            domain.to = ServerConfigFile::suffix_domain_with_port(&domain.from);
                        }
                    }
                }

                Ok(config)
            }

            fn suffix_domain_with_port(domain: &str) -> String {
                // Check if domain is supplied with port number
                if domain.contains(":") {
                    // If not supplied, suffix with the SERVER_PORT
                    format!("{}:{}", domain, Config::get_server_port())
                } else {
                    domain.to_string()
                }
            }
            pub fn domain_to_url(&self, domain: &str) -> Result<url::Url, url::ParseError> {
                Ok(url::Url::parse(&format!("{}://{}", self.protocol, domain))?)
            }
        }
    }

    impl Config {
        pub fn new(
            socket_address: SocketAddrV4,
            options: Option<HashMap<String, String>>,
            server_root: PathBuf,
            http_host: url::Url,
            config_file: config_file::ServerConfigFile,
        ) -> Self {
            Config {
                socket_address,
                options,
                server_root,
                http_host,
                config_file,
            }
        }

        /// Parses user defined args while executing the program
        pub fn parse_args(args: Vec<String>) -> Result<Config, Box<dyn Error>> {
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

            // Initialize the log file, open for appending

            // In all the above did not throw and error, we will set the environment variables
            // Set the SERVER_ROOT, SERVER_PUBLIC, SERVER_PORT environment variables
            // refer as std::env::var("SERVER_ROOT") to get the value
            std::env::set_var("SERVER_ROOT", &server_root);
            std::env::set_var("SERVER_PUBLIC", &server_root.join("public"));
            std::env::set_var("SERVER_PORT", socket_address.port().to_string());

            Ok(Config::new(
                socket_address,
                options,
                server_root,
                // This will normalize localhost and 127.0.0.1 in URL
                url::Url::parse(&format!("http://{}", socket_address))?,
                config_file::ServerConfigFile::get_config()?,
            ))
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
    use crate::database::DatabaseEntry;
    use http::{HttpRequestError, HttpResponseStartLine};
    use http_response::HttpResponse;
    use std::borrow::Cow;
    use std::fs::OpenOptions;
    use std::io::{self, BufRead, Read, Seek, Write};
    use std::path::Path;

    use crate::*;

    pub fn connect(config: &Config) -> Result<TcpListener, Box<dyn Error>> {
        return TcpListener::bind(config.socket_address).map_err(|e| e.into());
    }

    /// NOTE: Can log anything that implements `std::fmt::Display`
    ///
    /// Logs request or response that come from the client or response from the server to ./log.txt

    /// Sends error response to the client, based on the error that occurred during request handling
    /// downcasting to the specific error type from `Box<dyn Error>` and handling it accordingly
    ///
    /// If stream is None,
    /// If err is None, send default 500 Internal Server Error response
    fn send_error_response(
        config: &Config,
        stream: &mut TcpStream,
        // http_err: Option<&HttpRequestError>,
        mut err: Option<Box<dyn Error>>,
    ) -> Result<(), Box<dyn Error>> {
        let pages_path = std::path::Path::new("public/pages/");

        // If err is None, send default 500 Internal Server Error response
        if err.is_none() {
            err = Some(HttpRequestError::default().into())
        }

        if let Some(err) = err {
            let mut log_file = OpenOptions::new().append(true).open("logs/log.txt")?;
            log_file.write_all(format!("{err:#?}\r\n\r\n").as_bytes())?;

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
                return response.write(stream);
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

                return response.write(stream);
            }
            // NOTE: This is how you can handle different errors by downcasting to the specific error type
            // else if let Some(io_err) = err.downcast_ref::<std::io::Error>() {}
        } // You could propagate anything to the client there, for example for dev purposes:
          // NOTE: It propagates full error message to the client

        Ok(())
    }

    /// Starts TCP server with provided `Config`, continuously listens for incoming request and propagates them further.
    pub fn run_tcp_server(config: &Config) -> Result<(), Box<dyn Error>> {
        let listener = self::connect(config)?;

        println!(
            "TCP Connection Established at {:?}\nListening...",
            listener.local_addr().unwrap()
        );

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    if let Err(err) = self::handle_client(&mut stream, &config) {
                        eprintln!("Error handling request: {}", err);
                        send_error_response(config, &mut stream, Some(err))?;
                    } else {
                        // Request termination
                        // println!("Request handled successfully")
                    }
                }
                Err(err) => eprintln!("Invalid TCP stream: {}", err),
            }
        }

        Ok(())
    }

    /// Reads `TcpStream` to statically allocated buffer 1024 bytes in size
    pub fn read_tcp_stream(stream: &mut TcpStream) -> Result<String, Box<dyn Error>> {
        // NOTE: Investigate how this works, as I practically copied it from GitHub
        // shoutout to the author https://github.com/thepacketgeek/rust-tcpstream-demo/tree/master/raw

        // for i in 1..100 {
        //     println!("BLOCKING! {}", i);
        // }

        // Maximum request payload is 1 MiB, could be too much
        let mut reader = io::BufReader::with_capacity(1024 * 1024 * 1024, stream);
        let buffer = reader.fill_buf()?.to_vec();

        // let mut buffer_line = Vec::<u8>::new();
        // reader.read_line(&mut buffer_line)?;

        reader.consume(buffer.len());

        let message = String::from_utf8(buffer).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Couldn't parse received string as utf8",
            )
        })?;

        println!("{reader:?}");

        // log_tcp_stream(config, &message)?;
        return Ok(message);
    }

    /// Handles incoming request from the client.
    fn handle_client(stream: &mut TcpStream, config: &Config) -> Result<(), Box<dyn Error>> {
        let request: HttpRequest<'_> = HttpRequest::new(config, stream)?;
        let mut response_headers: HttpHeaders<'_> = HttpResponse::new_headers(None);

        let (method, path) = (request.get_method(), request.get_path_segment(config)?);

        println!("Requesting: {:?} {}", method, path.display());

        // This will be executed for every request and try to match paths that should be redirected
        // although the only redirection that we are doing is from http://127.0.0.1:<port> to http://localhost:<port>
        // paths are defined in the config file under 'domain' field, for domains and path redirect in the "paths" field

        // Give back the reference supplied to the function
        if request.redirect_request(stream, config)? {
            return Ok(());
        };

        let response_body = match method {
            HttpRequestMethod::GET => Some(request.read_requested_resource(&mut response_headers)?),
            HttpRequestMethod::POST => {
                // This would return Path not found if the path does not exists
                // If we would want to make custom endpoints without actual path existence
                // then it should be rewritten

                let resource = request.get_absolute_resource_path()?;

                match path {
                    p if p == Path::new("database/data.json") => {
                        // Default already created, we are not changing anything else besides status code
                        // response_headers.start_line.as_mut().unwrap().status_code = 201;

                        let mut database =
                            OpenOptions::new().write(true).read(true).open(resource)?;

                        let mut buffer = Vec::<u8>::new();

                        database.read_to_end(&mut buffer).map_err(|e| {
                            eprintln!("Error reading database: {:#?}", e);
                            HttpRequestError {
                                status_code: 500,
                                status_text: String::from("Internal Server Error"),
                                ..Default::default()
                            }
                        })?;

                        let mut error = HttpRequestError {
                            content_type: Some(String::from("application/json")),
                            message: Some(String::from("Internal Server Error")),
                            ..Default::default()
                        };

                        let body = request
                            .get_body()
                            .ok_or_else(|| {
                                eprintln!("Request body is empty");

                                error.message = Some(String::from("Request body is empty"));
                                error.clone()
                            })?
                            .trim();

                        let entry = serde_json::from_str::<DatabaseEntry>(body).map_err(|e| {
                            eprintln!("Error deserializing database entry: {:#?}", e);
                            error.clone()
                        })?;

                        // Also there
                        let mut serialized = serde_json::from_slice::<Vec<DatabaseEntry>>(&buffer)
                            .map_err(|e| {
                                eprintln!("Error deserializing database: {:#?}", e);
                                error.clone()
                            })?;

                        serialized.push(entry);

                        database.seek(std::io::SeekFrom::Start(0))?;
                        database.set_len(0)?;

                        database.write_all(serde_json::to_vec(&serialized)?.as_slice())?;
                        database.flush()?;

                        Some(String::from("Ok"))
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

        let mut response: HttpResponse<'_> = HttpResponse::new(response_headers, response_body)?;

        response.write(stream)?;
        Ok(())
    }
}
