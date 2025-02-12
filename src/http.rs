use std::{
    borrow::Cow,
    collections::HashMap,
    fmt::Display,
    path::{Path, PathBuf},
    str::FromStr,
};

pub use request_request_line::{HttpRequestMethod, HttpRequestRequestLine};
pub use response_start_line::HttpResponseStartLine;
use serde::{Deserialize, Serialize};

// use crate::prelude::*;

#[derive(Debug)]
pub enum HttpProtocol {
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

mod request_request_line {
    use tokio::sync::MutexGuard;

    use super::{HttpProtocol, HttpRequestError};
    use crate::config::Config;
    use std::fmt::Display;
    use std::path::PathBuf;
    use std::str::FromStr;

    #[derive(Debug)]
    pub struct HttpRequestRequestLine {
        method: HttpRequestMethod,
        // NOTE: I think this should be absolute path to the resource on the server
        request_target: PathBuf,
        protocol: HttpProtocol,
    }

    // trait RequestLine {
    //     fn get_method(&self) -> &HttpRequestMethod;
    //     fn get_protocol(&self) -> &HttpProtocol;
    //     fn get_request_target(&self) -> &PathBuf;
    // }

    impl<'a> HttpRequestRequestLine {
        pub async fn new(
            config: &MutexGuard<'_, Config>,
            line: &'a str,
        ) -> Result<Self, HttpRequestError> {
            let fields = line.split_whitespace().collect::<Vec<&'a str>>();

            let [method, request_target, protocol] = fields
                .get(0..3)
                .ok_or_else(|| {
                    eprintln!("Bad Request line: {:?}", fields);
                    HttpRequestError {
                        status_code: 400,
                        status_text: String::from("Bad Request"),
                        ..Default::default()
                    }
                })?
                .try_into()
                .map_err(|e| {
                    eprint!("Error converting slice to array: {}", e);
                    HttpRequestError {
                        status_code: 400,
                        status_text: String::from("Bad Request"),
                        ..Default::default()
                    }
                })?;

            let base_path = Config::get_server_public();

            // This maps the request_target to the actual file on the server
            // resolving "/" to the index.html file
            let request_target: PathBuf = match request_target {
                // "pages/index.html"
                p if p == "/" => base_path.join(config.get_index_path()),
                p => base_path.join(p.strip_prefix("/").unwrap()),
            };

            Ok(Self {
                method: HttpRequestMethod::from_str(method)?,
                protocol: HttpProtocol::from_str(protocol)?,
                request_target,
            })
        }

        pub(super) fn get_method(&self) -> &HttpRequestMethod {
            &self.method
        }

        pub(super) fn get_protocol(&self) -> &HttpProtocol {
            &self.protocol
        }

        pub(super) fn get_request_target(&self) -> &PathBuf {
            &self.request_target
        }
    }

    #[derive(Debug, PartialEq, Clone)]
    pub enum HttpRequestMethod {
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
}
mod response_start_line {
    use super::HttpProtocol;

    #[derive(Debug)]
    pub struct HttpResponseStartLine<'a> {
        protocol: HttpProtocol,
        // status_code should be typed for all available status codes
        status_code: u16,
        status_text: Option<&'a str>,
    }

    impl<'a> HttpResponseStartLine<'a> {
        pub fn new(protocol: HttpProtocol, status_code: u16, status_text: &'a str) -> Self {
            Self {
                protocol,
                status_code,
                status_text: status_text.into(),
            }
        }

        pub(super) fn get_protocol(&self) -> &HttpProtocol {
            &self.protocol
        }

        pub(super) fn get_status_code(&self) -> u16 {
            self.status_code
        }

        pub(super) fn get_status_text(&self) -> Option<&str> {
            self.status_text
        }
    }

    impl<'a> std::fmt::Display for HttpResponseStartLine<'a> {
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
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// `status_code` and `status_text` are specific to the HTTP protocol, specifically the start line of HTTP message
/// `content_type` is used to return appropriate response to the client
/// `message` is used to inform the user about the error, not standardized in HTTP
pub struct HttpRequestError {
    pub status_code: u16,
    pub status_text: String,
    pub content_type: Option<String>,
    pub message: Option<String>,
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
            "HTTP Error {}: {} ({})",
            self.status_code,
            self.status_text,
            self.message.to_owned().unwrap_or("None".to_string())
        )
    }
}

impl std::error::Error for HttpRequestError {}

impl From<HttpRequestError> for std::io::Error {
    fn from(err: HttpRequestError) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, err.to_string())
    }
}

// HttpRequestMethod::new("GET") -> HttpRequestMethod::GET
impl FromStr for HttpRequestMethod {
    type Err = HttpRequestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "GET" => Ok(HttpRequestMethod::GET),
            "POST" => Ok(HttpRequestMethod::POST),
            "DELETE" => Ok(HttpRequestMethod::DELETE),
            "UPDATE" => Ok(HttpRequestMethod::UPDATE),
            "PUT" => Ok(HttpRequestMethod::PUT),
            _ => Err(HttpRequestError {
                status_code: 501,
                status_text: String::from("Not Implemented"),
                ..Default::default()
            }),
        }
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
pub struct HttpHeaders<'a> {
    headers: HashMap<Cow<'a, str>, Cow<'a, str>>,
    start_line: Option<HttpResponseStartLine<'a>>,
    request_line: Option<HttpRequestRequestLine>,
}

impl<'a> HttpHeaders<'a> {
    pub fn new(
        start_line: Option<HttpResponseStartLine<'a>>,
        request_line: Option<HttpRequestRequestLine>,
    ) -> HttpHeaders<'a> {
        HttpHeaders {
            headers: HashMap::<Cow<str>, Cow<str>>::new(),
            start_line,
            request_line,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Cow<str>> {
        self.headers.get(key)
    }

    // This should validate the correctness of the header line
    pub fn add_header_line(&mut self, line: String) -> () {
        // Header should not contain more than one delimiter of ": " also there should be not
        // CRLF's thought that would be handled by the Lines Iterator, thought we also need to check,
        // also the key is not empty, and if the value is not empty

        // Assuming all CRLF's are removed by the Lines iterator
        let [key, value]: [String; 2] = line
            .split(": ")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .try_into()
            .expect("Incorrect header. Request is malformed.");

        self.add(key.into(), value.into());
    }

    /// Here's the docs: https://datatracker.ietf.org/doc/html/rfc2616#section-14
    /// Suck on this <Writes on a rock, SASSY office reference>
    pub fn add(&mut self, key: Cow<'a, str>, value: Cow<'a, str>) {
        self.headers.insert(key, value);
    }

    /// I hate this, should be typed
    pub fn detect_mime_type(&self) -> &str {
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

                let requested_resource = self.get_request_target().unwrap();

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
    }

    // Those getters are basically re-exporting functionality on the embedded structs
    // It is impossible to access methods from the embedded structs directly
    // as they are relatively public to the http module

    pub fn get_request_line(&self) -> Option<&HttpRequestRequestLine> {
        self.request_line.as_ref()
    }

    pub fn get_method(&self) -> Option<&HttpRequestMethod> {
        self.get_request_line()
            .expect("Request line not found")
            .get_method()
            .into()
    }

    pub fn get_request_target(&self) -> Option<&PathBuf> {
        self.get_request_line()
            .expect("Request line not found")
            .get_request_target()
            .into()
    }

    pub fn get_request_protocol(&self) -> Option<&HttpProtocol> {
        self.get_request_line()
            .expect("Request line not found")
            .get_protocol()
            .into()
    }

    pub fn get_start_line(&self) -> Option<&HttpResponseStartLine> {
        self.start_line.as_ref()
    }

    pub fn get_status_code(&self) -> Option<u16> {
        self.get_start_line()
            .expect("Start line not found")
            .get_status_code()
            .into()
    }

    pub fn get_status_text(&self) -> Option<&str> {
        self.get_start_line()
            .expect("Start line not found")
            .get_status_text()
            .into()
    }

    pub fn get_response_protocol(&self) -> Option<&HttpProtocol> {
        self.get_start_line()
            .expect("Start line not found")
            .get_protocol()
            .into()
    }
    pub fn get_headers(&self) -> &HashMap<Cow<str>, Cow<str>> {
        &self.headers
    }
}
