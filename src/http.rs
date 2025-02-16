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

impl HttpProtocol {
    /// That is bad.
    pub fn simplify(&self) -> &str {
        match self {
            HttpProtocol::HTTP1 | HttpProtocol::HTTP1_1 => "http",
            // Lack of support for HTTP2
        }
    }
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
    use std::str::FromStr;

    #[derive(Debug)]
    pub struct HttpRequestRequestLine {
        method: HttpRequestMethod,
        /// This is a work around to store the Url as the request_target, as the library `url::Url` does not allow relative urls parsing.
        /// It is build with the domain, protocol in the config file and port under env.
        ///
        /// `NOTE`: No information is read from `request_target` other than it's path, changes to protocol and host part are only made to
        /// avoid ambiguity in requests. `request_target` is only read with a getter, that performs proper parsing.
        request_target: url::Url,
        protocol: HttpProtocol,
    }

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

            // How to handle request_target compatibility with URLs?.
            // 1. Postponed request line initialization
            // 2. Mutable reference to request_line to mutate the request target, that would be an issue as config is borrowed immutably
            // 3. Initialize request line as is, providing config http_host field as the scheme and port part of the URL (thought PORT may not
            // exists, but we could take that from the env) in the HttpRequestRequestLine::new(),
            // and then mutate the request target inside the Self::new() to the scheme and port number part of the URL
            // as the Http Host, assuming Http Host contains the port number, which I think is the case.

            let mut host = config.http_url.clone();

            // Remove leading root identifier from the request_target as that would end up redundant and invalid
            // The reason is doing parsing with url::Url you will end up with a double root after clearing the segments
            // and setting the new path segments. NOTE: The segments actually does not exists in the url that does come with the config.http_url
            // that is just for being overly cautious (look at this man, what you taking about, you and cautions...).

            let request_target = request_target.strip_prefix("/").unwrap_or(&request_target);

            host.path_segments_mut()
                .map_err(|_| {
                    eprint!("Error getting mutable segments of request_target");
                    HttpRequestError::default()
                })
                .map(|mut segments| {
                    segments.clear();
                    // Strip the leading "/" from the request_target as it already in the host, so that would be redundant and invalid also
                    segments.push(request_target);
                })?;

            let protocol: HttpProtocol = HttpProtocol::from_str(protocol)?;

            // Change the host header default protocol (scheme) used to the actual protocol used in the request
            // NOTE: This change is not critical, but we will not allow something that could be malicious.
            // It could be malicious if someone would for example set scheme to file://, thought that is handled by the library
            // thought the conversion of protocol would also fail earlier so not really an issue.
            // We want to have a stateful field in this struct and not throwing there would be "stateless".
            // Also in the current state of the app there is not HTTPS this is just useless.

            host.set_scheme(protocol.simplify()).map_err(|_| {
                eprint!("Error setting scheme to the request_target");
                HttpRequestError::default()
            })?;

            Ok(Self {
                method: HttpRequestMethod::from_str(method)?,
                request_target: host,
                protocol,
            })
        }

        pub(super) fn get_method(&self) -> &HttpRequestMethod {
            &self.method
        }

        pub(super) fn get_protocol(&self) -> &HttpProtocol {
            &self.protocol
        }

        pub(super) fn get_request_target(&self) -> &url::Url {
            &self.request_target
        }

        pub(super) fn get_request_target_mut(&mut self) -> &mut url::Url {
            &mut self.request_target
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

    // Those getters are basically re-exporting functionality on the embedded structs
    // It is impossible to access methods from the embedded structs directly
    // as they are relatively public to the http module

    pub fn get_request_line(&self) -> Option<&HttpRequestRequestLine> {
        self.request_line.as_ref()
    }

    // This should not be exposed to the user, only for internal use
    pub fn get_request_line_mut(&mut self) -> Option<&mut HttpRequestRequestLine> {
        self.request_line.as_mut()
    }

    pub fn get_method(&self) -> Option<&HttpRequestMethod> {
        self.get_request_line()
            .expect("Request line not found")
            .get_method()
            .into()
    }

    pub fn get_request_target(&self) -> Option<&url::Url> {
        self.get_request_line()
            .expect("Request line not found")
            .get_request_target()
            .into()
    }

    // This should not be exposed to the user, only for internal use
    pub fn get_request_target_mut(&mut self) -> Option<&mut url::Url> {
        self.get_request_line_mut()
            .expect("Request line not found")
            .get_request_target_mut()
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
