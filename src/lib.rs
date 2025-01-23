use std::collections::HashMap;
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

    pub struct Config {
        pub server_root: PathBuf,
        pub socket_address: SocketAddrV4,
        pub options: Option<HashMap<String, String>>,
        pub http_host: url::Url,
        // NOTE: It's not optional because in the near future we will create the file with default when the server starts
        pub config_file: config_file::ServerConfigFile,
    }

    // TODO: Config file should be generate when server is first started with some crap that is default and required
    // for server to work, like `protocol` field.
    pub mod config_file {
        use serde::Deserialize;

        use super::Config;
        use std::fs;

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
        pub struct ServerConfigFile {
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
                            // Check if domain is supplied with port number, because even thought
                            // this is invalid, we will allow it
                            // port number in http URL is right after the domain name
                            // so we could split the domain by `:` and check for the second element presence, parsing it accordingly

                            if let None = domain.from.split(':').collect::<Vec<&str>>().get(1) {
                                domain.from =
                                    format!("{}:{}", domain.from, std::env::var("SERVER_PORT")?);
                            }
                            if let None = domain.to.split(':').collect::<Vec<&str>>().get(1) {
                                domain.to =
                                    format!("{}:{}", domain.to, std::env::var("SERVER_PORT")?);
                            }
                        }
                    }
                }

                Ok(config)
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
            // Project base path
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

            // Set the SERVER_ROOT, SERVER_PUBLIC, SERVER_PORT environment variables
            // refer as std::env::var("SERVER_ROOT") to get the value
            std::env::set_var("SERVER_ROOT", &server_root);
            std::env::set_var("SERVER_PUBLIC", &server_root.join("public"));
            std::env::set_var("SERVER_PORT", socket_address.port().to_string());

            // println!("{:?}", std::env::var("SERVER_ROOT"));
            // println!("{:?}", std::env::var("SERVER_PUBLIC"));
            // println!("{:?}", std::env::var("SERVER_PORT"));

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
            PathBuf::from(std::env::var("SERVER_PUBLIC").unwrap())
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
            PathBuf::from(std::env::var("SERVER_ROOT").unwrap())
                .canonicalize()
                .expect("Server root path set in the SERVER_ROOT env does not exists")
        }

        pub fn get_server_port() -> String {
            std::env::var("SERVER_PORT").expect("server_port not set in the SERVER_PORT env")
        }
    }
}

pub mod tcp_handlers {
    use crate::database::DatabaseEntry;
    use serde::de::IntoDeserializer;
    use serde::{Deserialize, Serialize};
    use std::borrow::Cow;
    use std::fmt::Display;
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Seek, Write};
    use std::net;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;

    use crate::config::Config::{self};

    use crate::*;

    #[derive(Debug, Serialize, Deserialize, Clone)]
    /// `status_code` and `status_text` are specific to the HTTP protocol, specifically the start line of HTTP message
    /// `content_type` is used to return appropriate response to the client
    /// `message` is used to inform the user about the error, not standardized in HTTP
    struct HttpRequestError {
        status_code: u16,
        status_text: String,
        content_type: Option<String>,
        message: Option<String>,
    }

    impl Default for HttpRequestError {
        fn default() -> Self {
            Self {
                status_code: 500,
                status_text: String::from("Internal Server Error"),
                content_type: Some(String::from("text/html")),
                message: None,
            }
        }
    }

    impl Display for HttpRequestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "Something went wrong!\nStatus code: {}\n{}",
                self.status_code, self.status_text
            )
        }
    }
    impl std::error::Error for HttpRequestError {}

    impl From<HttpRequestError> for std::io::Error {
        fn from(err: HttpRequestError) -> std::io::Error {
            std::io::Error::new(std::io::ErrorKind::Other, err.to_string())
        }
    }

    #[derive(Debug)]
    struct HttpRequest<'a> {
        headers: String,
        parsed_headers: HttpHeaders<'a>,
        body: Option<String>,
    }

    #[derive(Debug)]
    enum HttpProtocol {
        HTTP1,
        HTTP1_1,
        // HTTP2, NOTE: HTTP2 uses frames not request lines so unsupported here.
    }

    impl FromStr for HttpProtocol {
        type Err = HttpRequestError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "HTTP/1" => Ok(HttpProtocol::HTTP1),
                "HTTP/1.1" => Ok(HttpProtocol::HTTP1_1),
                // NOTE: The server SHOULD generate a representation for the 505 response that describes why
                // that version is not supported and what other protocols are supported by that server.
                _ => Err(HttpRequestError {
                    status_code: 505,
                    status_text: String::from("HTTP Version Not Supported"),
                    ..Default::default()
                }),
            }
        }
    }

    impl Display for HttpProtocol {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                HttpProtocol::HTTP1 => write!(f, "HTTP/1"),
                HttpProtocol::HTTP1_1 => write!(f, "HTTP/1.1"),
            }
        }
    }

    #[derive(Debug)]
    struct HttpResponseStartLine<'a> {
        protocol: HttpProtocol,
        // status_code should be typed for all available status codes
        status_code: u16,
        status_text: Option<&'a str>,
    }

    impl<'a> HttpResponseStartLine<'a> {
        fn new(protocol: HttpProtocol, status_code: u16, status_text: &'a str) -> Self {
            Self {
                protocol,
                status_code,
                status_text: status_text.into(),
            }
        }
    }

    impl<'a> Display for HttpResponseStartLine<'a> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{} {} {}\r\n",
                self.protocol,
                self.status_code,
                self.status_text.unwrap()
            )
        }
    }

    #[derive(Debug, PartialEq, Clone)]
    enum HttpRequestMethod {
        GET,
        POST,
        DELETE,
        UPDATE,
        PUT,
    }

    impl Display for HttpRequestMethod {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    impl FromStr for HttpRequestMethod {
        type Err = HttpRequestError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "GET" => Ok(HttpRequestMethod::GET),
                "POST" => Ok(HttpRequestMethod::POST),
                "DELETE" => Ok(HttpRequestMethod::DELETE),
                "UPDATE" => Ok(HttpRequestMethod::UPDATE),
                _ => Err(HttpRequestError {
                    status_code: 501,
                    status_text: String::from("Not Implemented"),
                    ..Default::default()
                }),
            }
        }
    }

    // HttpRequestMethod::new("GET") -> HttpRequestMethod::GET

    #[derive(Debug)]
    struct HttpRequestRequestLine {
        method: HttpRequestMethod,
        // NOTE: I think this should be absolute path to the resource on the server
        request_target: PathBuf,
        protocol: HttpProtocol,
    }

    impl<'a> HttpRequestRequestLine {
        fn new(line: &'a str) -> Result<Self, HttpRequestError> {
            let fields = line.split_whitespace().collect::<Vec<&'a str>>();

            // Would hardly occur, if ever
            if fields.len() != 3 {
                return Err(HttpRequestError {
                    status_code: 400,
                    status_text: String::from("Bad Request line"),
                    ..Default::default()
                });
            }

            let [method, request_target, protocol] = fields
                .get(0..3)
                .ok_or_else(|| HttpRequestError {
                    status_code: 400,
                    status_text: String::from("Bad Request"),
                    ..Default::default()
                })?
                .try_into()
                .unwrap();

            let base_path = Config::get_server_public();

            let request_target: PathBuf = match request_target {
                p if p == "/" => base_path.join("pages/index.html"),
                p => {
                    base_path.join(p.strip_prefix("/").unwrap())
                    // NOTE: Canonicalize thrown an error when path does not exists
                    // We could call fs::canonicalize() to check if the path exists
                    // .canonicalize()?
                }
            };

            Ok(Self {
                method: HttpRequestMethod::from_str(method)?,
                protocol: HttpProtocol::from_str(protocol)?,
                request_target,
            })
        }
    }

    // TODO: Proper HttpHeaders parsing not implemented
    /// NOTE: Header builder could be implement because there is a strict format in which data should be received and sent
    /// From, rfc7230#section-3.1
    /// HTTP-message   = start-line
    /// *( header-field CRLF )
    /// CRLF
    /// \[ message-body \]
    ///
    /// beyond the common forms.
    /// message-header = field-name ":" \[ field-value \]
    /// field-name     = token
    /// field-value    = *( field-content | LWS )
    /// field-content  = <the OCTETs making up the field-value
    ///                  and consisting of either *TEXT or combinations
    ///                  of token, separators, and quoted-string>
    ///
    /// HttpResponse and HttpRequest compliant
    ///
    /// NOTE: Headers parsing are done on HttpRequest and HttpResponse separately
    /// because there is not need for functionality of Parsing String to HashMap for HttpResponse
    /// and vice versa for HttpRequest. If you want this functionality you could invoke the method
    /// on a "opposite" struct.
    #[derive(Debug)]
    struct HttpHeaders<'a> {
        headers: HashMap<Cow<'a, str>, Cow<'a, str>>,
        start_line: Option<HttpResponseStartLine<'a>>,
        request_line: Option<HttpRequestRequestLine>,
    }

    impl<'a> HttpHeaders<'a> {
        /// Here's the docs: https://datatracker.ietf.org/doc/html/rfc2616#section-14
        /// Suck on this <Writes on a rock, SASSY office reference>
        fn add(&mut self, key: Cow<'a, str>, value: Cow<'a, str>) {
            // self.headers.insert(key, value);
            self.headers.insert(key, value);
        }

        fn detect_mime_type(&self) -> &str {
            match self.headers.get("Content-Type") {
                Some(content_type) => return content_type,
                None => {
                    // If not found, look up for extension
                    // and return MIME type based on that
                    // We will use <request_target> field from HttpRequestRequestLine,
                    // if there is no extension, we will assume `text/plain`
                    // NOTE: It will fail if request_target does not have a extension,
                    // but we will leave that be for now. We could try to recognize the extension
                    // based on the bytes of the file, or just use the appropriate library.

                    let requested_resource = &self.request_line.as_ref().unwrap().request_target;

                    // If requested resource is root, return `text/html`
                    if requested_resource.as_path() == Path::new("/") {
                        return "text/html";
                    }

                    match requested_resource.extension() {
                        Some(extension) => {
                            // NOTE: That is controversial string conversion
                            return match extension.to_str().unwrap() {
                                "html" => "text/html",
                                "css" => "text/css",
                                "js" => "text/javascript",
                                "json" => "application/json",
                                "xml" => "application/xml",
                                "png" => "image/png",
                                "jpg" | "jpeg" => "image/jpeg",
                                "gif" => "image/gif",
                                "svg" => "image/svg+xml",
                                "ico" => "image/x-icon",
                                "webp" => "image/webp",
                                "mp4" => "video/mp4",
                                "webm" => "video/webm",
                                "ogg" => "audio/ogg",
                                "mp3" => "audio/mpeg",
                                "wav" => "audio/wav",
                                "flac" => "audio/flac",
                                "pdf" => "application/pdf",
                                "zip" => "application/zip",
                                "tar" => "application/x-tar",
                                "gz" => "application/gzip",
                                "bz2" => "application/x-bzip2",
                                "7z" => "application/x-7z-compressed",
                                "rar" => "application/vnd.rar",
                                "exe" => "application/x-msdownload",
                                "msi" => "application/x-msi",
                                "deb" => "application/vnd.debian.binary-package",
                                "rpm" => "application/x-rpm",
                                "apk" => "application/vnd.android.package-archive",
                                "jar" => "application/java-archive",
                                "war" => "application/java-archive",
                                "ear" => "application/java-archive",
                                "class" => "application/java-vm",
                                "py" => "text/x-python",
                                "rb" => "text/x-ruby",
                                "php" => "text/x-php",
                                "c" => "text/x-c",
                                "cpp" => "text/x-c++",
                                "h" => "text/x-c-header",
                                "hpp" => "text/x-c++-header",
                                "cs" => "text/x-csharp",
                                "java" => "text/x-java",
                                "kt" => "text/x-kotlin",
                                "rs" => "text/x-rust",
                                "go" => "text/x-go",
                                // Return default `text/plain` if all of the above fails
                                _ => "text/plain",
                            };
                        }
                        None => return "text/plain",
                    }
                }
            }

            // for (key, value) in self.headers.iter() {
            //     if key == &"Content-Type" {
            //         return value;
            //     }
            // }
        }
    }

    impl<'a> HttpRequest<'a> {
        // Creates new HttpRequest instance from TcpStream, reads the stream to UTF-8 String and parses the headers
        fn new(stream: &mut TcpStream) -> Result<Self, Box<dyn Error>> {
            // Parse the TCP stream
            let headers = read_tcp_stream(stream)?;
            let (parsed_headers, body) = Self::parse_headers(headers.clone())?;

            Ok(Self {
                headers,
                parsed_headers,
                body,
            })
        }

        // Parses headers from the String, returns HttpHeaders and optional body that comes with request
        // We know that `headers` is non empty stream read from TCPStream, UTF-8 encoded
        fn parse_headers(
            headers: String,
        ) -> Result<(HttpHeaders<'a>, Option<String>), Box<dyn Error>> {
            // Ignore the CRLF at both ends of headers

            let mut headers_iter = headers.trim().lines();

            let request_line: HttpRequestRequestLine = HttpRequestRequestLine::new(
                headers_iter.next().expect("Request line not found").trim(),
            )?;

            let method = request_line.method.clone();

            let mut parsed_headers = HttpRequest::new_headers(request_line);
            let mut body: Option<String> = None;

            for header in &mut headers_iter {
                // NOTE: I assume that empty header is not possible and the only indication of empty
                // string is a CRLF between headers and body

                // Consume rest of the iterator treating is as the body of the request
                if (header == "" || header == "\r\n")
                    && (method == HttpRequestMethod::POST
                        || method == HttpRequestMethod::UPDATE
                        || method == HttpRequestMethod::PUT)
                {
                    let rest = headers_iter.collect::<String>();
                    if rest.trim() != "" {
                        body = Some(rest);
                    } else {
                        // POST, PUT, UPDATE request with empty body
                    }

                    break;
                }

                let entry = header.split(": ").collect::<Vec<_>>();

                let (key, value) = entry
                    .get(0..2)
                    .map(|entry| (entry[0].to_string(), entry[1].to_string()))
                    // Termination there
                    .ok_or_else(|| HttpRequestError {
                        status_code: 400,
                        status_text: String::from("Bad Request"),
                        ..Default::default()
                    })?;

                parsed_headers.add(Cow::from(key), Cow::from(value));
            }

            return Ok((parsed_headers, body));
        }

        fn new_headers(request_line: HttpRequestRequestLine) -> HttpHeaders<'a> {
            HttpHeaders {
                headers: HashMap::<Cow<str>, Cow<str>>::new(),
                request_line: Some(request_line),
                start_line: None,
            }
        }

        // Make a getter
        fn get_method(&self) -> &HttpRequestMethod {
            &self.parsed_headers.request_line.as_ref().unwrap().method
        }

        /// Returns absolute path to the requested resource
        fn get_resource_path(&self) -> &PathBuf {
            &self
                .parsed_headers
                .request_line
                .as_ref()
                .unwrap()
                .request_target
        }

        /// Returns relative path to the requested resource
        ///
        /// Equivalent to http path that was given in the request
        fn get_resource_path_relative(&self) -> &Path {
            self.get_resource_path()
                // .canonicalize()
                .strip_prefix(Config::get_server_public())
                .unwrap()
        }

        /// Takes Response `HttpHeaders` and write `Content-Type` and `Content-Length` headers, returning the requested resource as a String
        /// Walks `/public` directory looking for path
        fn read_requested_resource(
            &'a self,
            // request: &'a HttpHeaders<'a>,
            response_headers: &mut HttpHeaders<'a>,
        ) -> Result<String, Box<dyn Error>> {
            let resource_path = self.get_resource_path();

            if let Ok(path) = resource_path.canonicalize() {
                let base = Config::get_server_root();

                let requested_path = match path.strip_prefix(&base) {
                    Ok(stripped) => stripped,
                    Err(_) => {
                        eprintln!("Base path is not a prefix of the requested path");
                        path.as_path()
                    }
                };

                println!("Requesting: {:?}", requested_path);

                // Read the file
                let requested_resource = fs::read_to_string(path)?;

                response_headers.add(
                    Cow::from("Content-Length"),
                    Cow::from(requested_resource.len().to_string()),
                );

                response_headers.add(
                    Cow::from("Content-Type"),
                    Cow::from(self.parsed_headers.detect_mime_type()),
                );

                return Ok(requested_resource);
            } else {
                // If path does not exists on the server, return 404
                // NOTE: We could return silent error messages instead of panicking the server

                eprintln!(
                    "Path not found: Requesting: {:?} Canonicalized: {:?}",
                    resource_path,
                    resource_path.canonicalize()
                );

                return Err(HttpRequestError {
                    status_code: 404,
                    status_text: String::from("Not Found"),
                    ..Default::default()
                })?;
            }
        }
    }

    #[derive(Debug)]
    struct HttpResponse<'a> {
        body: Option<String>, // This could be [u8] bytes Or just `Bytes` struct, because that is at the lower level and actually every resource in TCP is stream as chunks of u8 bytes.
        headers: HttpHeaders<'a>,
        serialized: Option<Vec<u8>>,
    }

    impl<'a> HttpResponse<'a> {
        /// Initializes HttpResponse and adds appropriate headers based on request_headers
        ///
        /// If request_headers are None, it means responding with some kind of critical error, regardless of the request

        // NOTE: I find it very stupid that writing headers is somehow automated
        // so we will opt out of that idea.
        fn new(
            response_headers: HttpHeaders<'a>,
            body: Option<String>,
        ) -> Result<Self, Box<dyn Error>> {
            // if let Some(request) = request {
            //     if let Some(start_line) = response_headers.start_line.as_ref() {
            //         match start_line.status_code {
            //             308 => {
            // response_headers.add(Cow::from("Content-Length"), Cow::from("0"));
            //             }
            //             _ => (),
            //         };
            //     }

            // match request.parsed_headers.request_line.as_ref().unwrap().

            //     request
            //         .parsed_headers
            //         .headers
            //         .iter()
            //         .for_each(|(key, value)| {
            //             match key.as_ref() {
            //                 "Connection" => {
            //                     response_headers.add(Cow::from("Connection"), value.clone())
            //                 }
            //                 // "Origin" => {
            //                 //     // NOTE: That could be useless
            //                 //     let origin_url =
            //                 //         url::Url::parse(value).expect("Invalid origin header");

            //                 //     if let Some(url) = &mut url {
            //                 //         if let Some(host) = origin_url.host_str() {
            //                 //             // Normalize loopback address
            //                 //             if host == "127.0.0.1" || host == "localhost" {
            //                 //                 url.set_host(Some(host))
            //                 //                     .expect("Invalid hostname for url");
            //                 //             }
            //                 //         }

            //                 //         response_headers.add(
            //                 //             Cow::from("Access-Control-Allow-Origin"),
            //                 //             url.to_string().into(),
            //                 //         )
            //                 //     }
            //                 // }
            //                 _ => (),
            //             }
            //             // Know you can implement every single response header based on the request headers
            //             // The problem is that you have to know what to do with every header
            //             // Responding to the request headers is not a straightforward task
            //             // because every path and every method should be handled differently
            //         });
            // }

            Ok(Self {
                body,
                headers: response_headers,
                serialized: None,
            })
        }

        /// Initializes HttpHeaders with start line, providing default value for headers field with `HashMap::<&str, Cow<str>>::new()`
        /// Start line is initialized with `HTTP/1.1 200 OK` status code and status text,
        /// any errors and changes to start line COULD be done after initialization on the mutable reference to the headers
        /// or by providing custom start line as an argument to the function.
        fn new_headers(start_line: Option<HttpResponseStartLine<'a>>) -> HttpHeaders<'a> {
            HttpHeaders {
                headers: HashMap::<Cow<str>, Cow<str>>::new(),
                start_line: match start_line {
                    Some(start_line) => Some(start_line),
                    None => Some(HttpResponseStartLine {
                        protocol: HttpProtocol::HTTP1_1,
                        status_code: 200,
                        status_text: Some("OK"),
                    }),
                },
                request_line: None,
            }
        }

        /// Parses headers field  from HashMap<String, String> and body to Vec<u8> bytes vector and saves it in parsed_headers field
        fn parse_http_message(&mut self) -> Option<&Vec<u8>> {
            // In theory, data returned from this function is a REFERENCE to headers field
            // so we should be able to return a reference to underlining data instead of owning it explicitly
            // We should probably allocate some static buffer of size self.headers.len() + self.body.len() + 1024

            // CONCLUSION: We could allocate static size buffer but this is just unnecessary and error prone,
            // using reference is impossible because we are parsing the data in self.headers and self.start_line]
            // making it own the data underneath effectively coping the data from headers with additional overhead,
            // so we need to allocate the buffer that owns every chunk of parsed data.

            // In theory this could return an error when data is semantically incorrect
            // then parsing would fail

            let mut buffer = Vec::<u8>::new();

            // start-line formatting
            buffer.extend(
                self.headers
                    .start_line
                    .as_ref()
                    .unwrap()
                    .to_string()
                    .as_bytes(),
            );

            // headers formatting
            buffer.extend(&self.headers.headers.iter().fold(
                Vec::<u8>::new(),
                |mut acc, (key, value)| {
                    acc.extend(format!("{key}: {value}\r\n").as_bytes());
                    acc
                },
            ));

            // injecting additional; CRLF before body
            buffer.extend("\r\n".as_bytes());

            // body formatting
            if let Some(body) = &self.body {
                buffer.extend(body.as_bytes());
            }
            // NOTE: Generally speaking saving parsed_headers is useless after we sent the response
            self.serialized = Some(buffer);

            self.serialized.as_ref()
        }

        fn write(&mut self, stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
            // We could invoke the headers writing match statement here

            log_tcp_stream(format!("--- Response ---\n{:#?}\r\n", self.headers))?;

            stream.write_all(self.parse_http_message().unwrap())?;
            stream.flush()?;

            stream.shutdown(net::Shutdown::Write)?;
            Ok(())
        }
    }

    pub fn connect(config: &Config) -> Result<TcpListener, Box<dyn Error>> {
        return TcpListener::bind(config.socket_address).map_err(|e| e.into());
    }

    /// NOTE: Can log anything that implements `std::fmt::Display`
    ///
    /// Logs request or response that come from the client or response from the server to ./log.txt
    fn log_tcp_stream<T: Display>(stream: T) -> Result<(), Box<dyn Error>> {
        let file_log_path = Path::new("logs/log.txt");
        let mut file_log = OpenOptions::new()
            .append(true)
            .truncate(false)
            .open(file_log_path)?;

        file_log.write_all(stream.to_string().trim().as_bytes())?;
        file_log.write_all("\r\n\r\n".as_bytes())?;
        file_log.flush()?;

        Ok(())
    }

    /// Sends error response to the client, based on the error that occurred during request handling
    /// downcasting to the specific error type from `Box<dyn Error>` and handling it accordingly
    ///
    /// If stream is None,
    /// If err is None, send default 500 Internal Server Error response
    fn send_error_response(
        stream: &mut TcpStream,
        // http_err: Option<&HttpRequestError>,
        mut err: Option<Box<dyn Error>>,
    ) -> Result<(), Box<dyn Error>> {
        let pages_path = std::path::Path::new("public/pages/");

        // If err is None, send default 500 Internal Server Error response
        if err.is_none() {
            err = Some(Box::new(HttpRequestError::default()))
        }

        if let Some(err) = err {
            let mut log_file = OpenOptions::new().append(true).open("logs/log.txt")?;
            log_file.write_all(format!("{err:?}\r\n").as_bytes())?;

            if let Some(http_err) = err.downcast_ref::<HttpRequestError>() {
                // This branch is also called when `err` is not suppliedS

                // JAMMING: If you want to send error response as a page to the client it could be done
                // JAMMING: if it is requested from an entity that can interpret the HTML
                // JAMMING: For example, given POST request, you COULD NOT response with an HTML page
                // JAMMING: that would be shown in the browser, client would receive the HTML page, but could not interpret it
                // JAMMING: In this instance we need to create custom TcpStream instead writing to the existing one
                // JAMMING: We should also respond to the client with some information about moved request or redirection

                let mut response_headers = HttpResponse::new_headers(
                    HttpResponseStartLine::new(
                        HttpProtocol::HTTP1_1,
                        http_err.status_code,
                        &http_err.status_text,
                    )
                    .into(),
                );

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
                eprintln!("Error handling request: {:#?}", err);

                let mut headers = HttpResponse::new_headers(
                    HttpResponseStartLine::new(HttpProtocol::HTTP1_1, 500, "Internal Server Error")
                        .into(),
                );

                headers.add(Cow::from("Content-Type"), Cow::from("text/plain"));

                let body = format!("Error handling request:\n{:#?}", err);

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
    pub fn run_tcp_server(config: Config) -> Result<(), Box<dyn Error>> {
        let listener = self::connect(&config)?;

        println!(
            "TCP Connection Established at {:?}\nListening...",
            listener.local_addr().unwrap()
        );

        // TODO: Make the logging file initialization somewhere else,
        // Obscure logging, make the file when
        let tcp_file_log_path = Path::new("logs/log.txt");
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(tcp_file_log_path)?;

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    if let Err(err) = self::handle_client(&mut stream, &config) {
                        eprintln!("Error handling request: {:#?}", err);
                        send_error_response(&mut stream, Some(err))?;
                    } else {
                        // Request termination
                        // println!("Request handled successfully")
                    }
                }
                Err(err) => eprintln!("Invalid TCP client stream: {}", err),
            }
        }

        Ok(())
    }

    /// Reads `TcpStream` to statically allocated buffer 1024 bytes in size
    fn read_tcp_stream(stream: &mut TcpStream) -> Result<String, Box<dyn Error>> {
        // Conclusion you have to read the incoming request to handle response
        // and the buffer has to be statically allocated because somehow dynamic memory allocation
        // fails us, nothing new.

        // NOTE: That buffer may overflow
        let mut buffer = [0u8; 1024];
        let bytes_read = stream.read(&mut buffer)?;
        stream.flush()?;

        if bytes_read == 0 {
            return Err("No bytes read from the stream".into());
        }

        if buffer
            .iter()
            .fold(0, |acc, &ele| if ele != 0 { acc + 1 as i32 } else { acc })
            >= 1024
        {
            println!("NOTE: !!! Buffer could be overflown !!!");
        }

        let message_decoded = String::from_utf8_lossy(&buffer[0..bytes_read]).to_string();

        log_tcp_stream(&message_decoded)?;

        return Ok(message_decoded);
    }

    /// This function is not meant to work as a redirection to specified URL
    /// Instead we will configure paths that should be redirected
    ///
    /// Configuration is derived from `config/config.json`
    ///
    /// Return bool indicating if the request was redirected
    fn redirect_request<'a>(
        request: &'a HttpRequest<'a>,
        stream: &mut TcpStream,
        config: &'a Config,
    ) -> Result<bool, Box<dyn Error>> {
        // if Host is http://127.0.0.1:5000 then redirect the request to http://localhost:5000
        // QUESTION: Should request be supplied?
        // No if we're redirecting based on config file, that is useless
        // Doing it based on request in runtime would be basically hardcoding the paths

        // We need to make new request, that would require to instantiate new TCPStream
        // write appropriate headers, also take note that what we are doing is server side navigation
        // We could think about taking information about incoming request actually based on the request supplied
        // Because think about it, request to 127.0.0.1:<port> comes in, it could be GET or POST or whatever,
        // and we have to make sure that no request and no method will reach that path because it is corrupted,
        // So yeah it would be useful if we could just make the browser write the request
        // but we can't cause we are on the SERVER!. Given that we actually need to rewrite that request,
        // take the headers that was sent to the server and rewrite them to the new request, that is the only way

        // Does not make sens because the request is already sent so changing its headers is useless
        // We need to create new request with new Host header and respond to the previous one with 301 Moved Permanently

        // Something to think about
        // Note: In the Fetch Standard, when a user agent receives a 301 in response to a POST request,
        // it uses the GET method in the subsequent redirection request, as permitted by the HTTP specification.
        // To avoid user agents modifying the request, use 308 Permanent Redirect instead,
        // as altering the method after a 308 response is prohibited.

        for (key, value) in request.parsed_headers.headers.iter() {
            match key.as_ref() {
                "Host" => {
                    if let Some(redirect) = &config.config_file.redirect {
                        // Redirection to domains
                        if let Some(domains) = &redirect.domains {
                            for domain in domains {
                                // We need to match incoming request to domain.from to redirect it to domain.to
                                if value.to_string() == domain.from {
                                    // Write 301 Moved Permanently || 308 Permanent Redirect to the stream, supply the Location header
                                    // We will use 308

                                    let mut response_headers = HttpResponse::new_headers(
                                        HttpResponseStartLine::new(
                                            HttpProtocol::HTTP1_1,
                                            308,
                                            "Permanent Redirect",
                                        )
                                        .into(),
                                    );

                                    // Redirecting to Location we should remember that
                                    // when we do POST request to some URL with a path
                                    // like database/data.json we should set the location header
                                    // not only to the domain but also suffix it with the incoming path
                                    // for request to be valid and correctly redirected

                                    // NOTE: What if domain is invalid and the path is invalid
                                    // then we would have to redirect both.

                                    // NOTE: Macro for writing headers would be great
                                    let mut location =
                                        config.config_file.domain_to_url(&domain.to)?;

                                    location.set_path(
                                        request.get_resource_path_relative().to_str().unwrap(),
                                    );

                                    response_headers
                                        .add("Location".into(), location.to_string().into());

                                    response_headers
                                        .add(Cow::from("Content-Length"), Cow::from("0"));

                                    let mut response: HttpResponse<'_> =
                                        HttpResponse::new(response_headers, None)?;

                                    response.write(stream)?;
                                    return Ok(true);
                                }
                            }
                        }
                    }
                }
                // To redirect based on paths you need to match appropriate header, maybe Referer, than we will parse to url::Url
                // and try to match the path to the one in the config file
                _ => (),
            }
        }
        // println!("{request:?}");
        Ok(false)
    }

    /// Handles incoming request from the client.
    fn handle_client(stream: &mut TcpStream, config: &Config) -> Result<(), Box<dyn Error>> {
        let request: HttpRequest<'_> = HttpRequest::new(stream)?;
        let mut response_headers: HttpHeaders<'_> = HttpResponse::new_headers(None);

        // This will be executed for every request and try to match paths that should be redirected
        // although the only redirection that we are doing is from http://127.0.0.1:<port> to http://localhost:<port>
        // paths are defined in the config file under 'domain' field, for domains and path redirect in the "paths" field

        // Give back the reference supplied to the function
        if redirect_request(&request, stream, config)? {
            return Ok(());
        };

        // --- How to handle POST requests ---
        let request_method = request.get_method();

        let response_body = match request_method {
            HttpRequestMethod::GET => Some(request.read_requested_resource(&mut response_headers)?),
            HttpRequestMethod::POST => {
                // This would return Path not found if the path does not exists
                // If we would want to make custom endpoints without actual path existence
                // then it should be rewritten

                let resource = request.get_resource_path().canonicalize()?;
                let path = resource.strip_prefix(Config::get_server_public())?;

                println!("Response body POST path: {path:?}");

                match path {
                    p if p == Path::new("database/data.json") => {
                        // Default already created, we are not changing anything else besides status code
                        // response_headers.start_line.as_mut().unwrap().status_code = 201;

                        let mut database =
                            OpenOptions::new().write(true).read(true).open(resource)?;
                        let mut buffer = Vec::<u8>::new();

                        database.read_to_end(&mut buffer)?;

                        let error = HttpRequestError {
                            content_type: Some(String::from("application/json")),
                            message: Some(String::from("Internal Server Error")),
                            ..Default::default()
                        };

                        println!("Post body: {:?}", request.body);
                        let body = request.body.as_ref().ok_or(error.clone())?;

                        // At this point we could throw error to client
                        let entry = serde_json::from_str::<DatabaseEntry>(body)?;

                        // Also there
                        let mut serialized = serde_json::from_slice::<Vec<DatabaseEntry>>(&buffer)?;

                        serialized.push(entry);

                        database.seek(std::io::SeekFrom::Start(0))?;
                        database.set_len(0)?;

                        database.write_all(serde_json::to_vec(&serialized)?.as_slice())?;
                        database.flush()?;

                        Some(String::from("Ok"))
                    }
                    _ => {
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
