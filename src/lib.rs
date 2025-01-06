use std::collections::HashMap;
use std::error::Error;
use std::net::{SocketAddrV4, TcpListener, TcpStream};
use std::path::PathBuf;

pub struct Config {
    server_root: PathBuf,
    host: SocketAddrV4,
    options: Option<HashMap<String, String>>,
}

impl Config {
    pub fn new(
        host: SocketAddrV4,
        options: Option<HashMap<String, String>>,
        server_root: PathBuf,
    ) -> Self {
        // Project base path
        Config {
            host,
            options,
            server_root,
        }
    }

    /// Parses user defined args while executing the program
    pub fn parse_args(args: Vec<String>) -> Result<Config, Box<dyn Error>> {
        if args.len() < 2 {
            return Err(format!("Usage: {} <address:port> [server_root_path]", args[0]).into());
        }

        let host = args[1].parse::<SocketAddrV4>()?;
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
                    let default_path = std::env::current_dir()?.join("public");
                    println!("Using: {:?} as server_root", default_path);
                    Ok(default_path)
                })?,
        };

        // Set the SERVER_ROOT environment variable
        // refer as std::env::var("SERVER_ROOT") to get the value
        std::env::set_var("SERVER_ROOT", &server_root);

        Ok(Config::new(host, options, server_root))
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
    pub fn get_server_root() -> PathBuf {
        PathBuf::from(std::env::var("SERVER_ROOT").unwrap())
    }
}

pub mod tcp_handlers {
    use std::borrow::Cow;
    use std::fmt::Display;
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};
    use std::net;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;

    use crate::Config;
    use crate::*;

    // NOTE: This should be propagated to user if it occurs
    #[derive(Debug)]
    struct HttpRequestError {
        status_code: u16,
        status_text: String,
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
        parsed_headers: Option<HttpHeaders<'a>>,
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

    #[derive(Debug)]
    enum HttpRequestMethod {
        GET,
        POST,
        DELETE,
        UPDATE,
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
                });
            }

            let [method, request_target, protocol] = fields
                .get(0..3)
                .ok_or_else(|| HttpRequestError {
                    status_code: 400,
                    status_text: String::from("Bad Request"),
                })?
                .try_into()
                .unwrap();

            let base_path = Config::get_server_root();

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
            for (key, value) in self.headers.iter() {
                if key == &"Content-Type" {
                    return value;
                }
            }

            // If for loop did not terminate, look up for extension
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

    impl<'a> HttpRequest<'a> {
        // Creates new HttpRequest instance from TcpStream, reads the stream to UTF-8 String and parses the headers

        fn new(stream: &mut TcpStream) -> Result<Self, Box<dyn Error>> {
            // Parse the TCP stream
            let headers = read_tcp_stream(stream)?;
            let parsed_headers = Some(Self::parse_headers(headers.clone())?);

            Ok(Self {
                headers,
                parsed_headers,
            })
        }

        fn parse_headers(headers: String) -> Result<HttpHeaders<'a>, Box<dyn Error>> {
            //   Ignore the CRLF at both ends of headers
            let mut headers_iter = headers.trim().lines();

            let request_line: HttpRequestRequestLine = HttpRequestRequestLine::new(
                headers_iter.next().expect("Request line not found").trim(),
            )?;

            let mut parsed_headers = HttpRequest::new_headers(request_line);

            // NOTE: If you want some advanced parsing
            // 1. Header name and header value is separated by `:` character
            // 2. Value separated by "," could contain additional delimiters like `;` -> (this signal that value after that is delimited by ";" and contains key=value pair, like q=0.9) or `=`
            //  2.2 If the value contains `,` character it should be collected to a Vector
            //  2.3. If the value contains `=` character it should be split into key-value pair
            //  2.4. (Unsupported) Values could also be wrapped in parentheses, and follow recursive parsing rules,
            //      meaning all of the above rules apply to the value inside the parentheses, they create a separate group of value parsing.

            for header in headers_iter {
                let entry = header.split(": ").collect::<Vec<_>>();

                let (key, value) = entry
                    .get(0..2)
                    .map(|entry| (entry[0].to_string(), entry[1].to_string()))
                    .ok_or_else(|| HttpRequestError {
                        status_code: 400,
                        status_text: String::from("Bad Request"),
                    })?;

                parsed_headers.add(Cow::from(key), Cow::from(value));
            }

            Ok(parsed_headers)
        }

        fn new_headers(request_line: HttpRequestRequestLine) -> HttpHeaders<'a> {
            HttpHeaders {
                headers: HashMap::<Cow<str>, Cow<str>>::new(),
                request_line: Some(request_line),
                start_line: None,
            }
        }

        /// Takes Response `HttpHeaders` and write `Content-Type` and `Content-Length` headers, returning the requested resource as a String
        fn read_requested_resource(
            &'a mut self,
            // request: &'a HttpHeaders<'a>,
            response_headers: &mut HttpHeaders<'a>,
        ) -> Result<String, Box<dyn Error>> {
            let resource_path = &self
                .parsed_headers
                .as_ref()
                .unwrap()
                .request_line
                .as_ref()
                .unwrap()
                .request_target;

            if let Ok(path) = resource_path.canonicalize() {
                println!("Requesting: {:?}", path);

                // Read the file
                let requested_resource = fs::read_to_string(path)?;

                response_headers.add(
                    Cow::from("Content-Length"),
                    Cow::from(requested_resource.len().to_string()),
                );

                response_headers.add(
                    Cow::from("Content-Type"),
                    Cow::from(self.parsed_headers.as_ref().unwrap().detect_mime_type()),
                );

                return Ok(requested_resource);
            } else {
                // If path does not exists on the server, return 404
                // NOTE: We could return silent error messages instead of panicking the server

                println!(
                    "Path not found: Requesting: {:?} Canonicalized: {:?}",
                    resource_path,
                    resource_path.canonicalize()
                );

                return Err(HttpRequestError {
                    status_code: 404,
                    status_text: String::from("Not Found"),
                })?;
            }
        }
    }

    #[derive(Debug)]
    struct HttpResponse<'a> {
        body: Option<String>, // This could be &[u8] bytes Or just `Bytes` struct, because that is at the lower level and actually every resource in TCP is stream as chunks of u8 bytes.
        headers: HttpHeaders<'a>,
        serialized: Option<Vec<u8>>,
    }

    impl<'a> HttpResponse<'a> {
        fn new(headers: HttpHeaders<'a>, body: String) -> Self {
            Self {
                body: Some(body),
                headers,
                serialized: None,
            }
        }

        /// Initializes HttpHeaders with start line, providing default value for headers field with `HashMap::<&str, Cow<str>>::new()`
        fn new_headers(start_line: HttpResponseStartLine<'a>) -> HttpHeaders<'a> {
            HttpHeaders {
                headers: HashMap::<Cow<str>, Cow<str>>::new(),
                start_line: Some(start_line),
                request_line: None,
            }
        }

        /// Parses headers field  from HashMap<String, String> and body to Vec<u8> bytes vector and saves it in parsed_headers field
        fn parse_headers(&mut self) -> Option<&Vec<u8>> {
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
            buffer.extend(self.body.as_ref().unwrap().as_bytes());

            // NOTE: Generally speaking saving parsed_headers is useless after we sent the response
            self.serialized = Some(buffer);

            self.serialized.as_ref()
        }
    }

    pub fn connect(config: &Config) -> Result<TcpListener, Box<dyn Error>> {
        return TcpListener::bind(config.host).map_err(|e| e.into());
    }

    /// NOTE: Can log anything that implements `std::fmt::Display`
    ///
    /// Logs request or response that come from the client or response from the server to ./log.txt
    fn log_tcp_stream<T: Display>(stream: T) -> Result<(), Box<dyn Error>> {
        let file_log_path = Path::new("log.txt");
        let mut file_log = OpenOptions::new()
            .append(true)
            .truncate(false)
            .open(file_log_path)?;

        file_log.write_all(stream.to_string().as_bytes())?;
        file_log.write_all("\r\n".as_bytes())?;
        file_log.flush()?;

        Ok(())
    }

    /// Sends error response to the client, based on the error that occurred during request handling
    /// downcasting to the specific error type from `Box<dyn Error>` and handling it accordingly
    fn send_error_response(
        stream: &mut TcpStream,
        // http_err: Option<&HttpRequestError>,
        err: Option<Box<dyn Error>>,
    ) -> Result<(), Box<dyn Error>> {
        let pages_path = std::path::Path::new("public/pages/");
        let html_file_data = std::fs::read_to_string(pages_path.join("error.html"))?;

        match err {
            Some(err) => {
                if let Some(http_err) = err.downcast_ref::<HttpRequestError>() {
                    let start_line = HttpResponseStartLine {
                        protocol: HttpProtocol::HTTP1_1,
                        status_code: http_err.status_code,
                        status_text: Some(&http_err.status_text),
                    };

                    let mut response_headers = HttpResponse::new_headers(start_line);

                    response_headers.add(Cow::from("Content-Type"), Cow::from("text/html"));
                    response_headers.add(
                        Cow::from("Content-Length"),
                        Cow::from(html_file_data.len().to_string()),
                    );

                    let mut response = HttpResponse::new(response_headers, html_file_data);
                    stream.write_all(response.parse_headers().unwrap().as_ref())?;
                    stream.flush()?;
                }
                // NOTE: This is how you can handle different errors by downcasting to the specific error type
                // else if let Some(io_err) = err.downcast_ref::<std::io::Error>() {}
                else {
                    // You could propagate anything to the client there, for example for dev purposes:
                    // NOTE: It propagates full error message to the client
                    eprintln!("Error handling request: {:#?}", err);

                    let start_line = HttpResponseStartLine {
                        protocol: HttpProtocol::HTTP1_1,
                        status_code: 500,
                        status_text: Some("Internal Server Error"),
                    };
                    let mut headers = HttpResponse::new_headers(start_line);

                    headers.add(Cow::from("Content-Type"), Cow::from("text/plain"));
                    let body = format!("Error handling request:\n{:#?}", err);
                    headers.add(
                        Cow::from("Content-Length"),
                        Cow::from(body.len().to_string()),
                    );

                    let mut response = HttpResponse::new(headers, body);

                    stream.write_all(response.parse_headers().unwrap().as_ref())?;
                    stream.flush()?;
                }
            }
            None => panic!("Error handling request: {:#?}", err),
        }

        stream.shutdown(net::Shutdown::Write)?;
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
        let tcp_file_log_path = Path::new("log.txt");
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(tcp_file_log_path)?;

        for stream in listener.incoming() {
            println!("Incoming request: {:?}", stream);

            match stream {
                Ok(mut stream) => match self::handle_client(&mut stream) {
                    Ok(_) => println!("Request handled successfully"),
                    Err(err) => send_error_response(&mut stream, Some(err))?,
                },
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

        let mut buffer = [0u8; 1024];
        let bytes_read = stream.read(&mut buffer)?;
        stream.flush()?;

        if bytes_read == 0 {
            return Err("No bytes read from the stream".into());
        }

        let message_decoded = String::from_utf8_lossy(&buffer[0..bytes_read]).to_string();

        log_tcp_stream(&message_decoded)?;

        return Ok(message_decoded);
    }

    /// Handles incoming request from the client.
    fn handle_client(stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
        let mut request: HttpRequest<'_> = HttpRequest::new(stream)?;

        // TODO: This should also be dynamic
        let response_start_line = HttpResponseStartLine {
            protocol: HttpProtocol::HTTP1_1,
            status_code: 200,
            status_text: Some("OK"),
        };

        let mut response_headers = HttpResponse::new_headers(response_start_line);
        let requested_resource = request.read_requested_resource(&mut response_headers)?;

        // Attach headers
        response_headers.add(Cow::from("Connection"), Cow::from("keep-alive"));

        log_tcp_stream(format!("--- Response ---\n{:#?}\n", response_headers))?;
        let mut response = HttpResponse::new(response_headers, requested_resource);

        stream.write_all(response.parse_headers().unwrap())?;
        stream.flush()?;

        stream.shutdown(net::Shutdown::Write)?;
        Ok(())
    }
}
