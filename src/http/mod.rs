pub mod http_request;
pub mod http_response;

use crate::config::SpecialDirectories;
use crate::prelude::*;
use crate::{config::Config, http_response::HttpResponse};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::{borrow::Cow, collections::HashMap, error::Error, fmt::Display, str::FromStr};
use strum::IntoEnumIterator;
use tokio::{net::tcp::OwnedWriteHalf, sync::MutexGuard};
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

#[derive(Debug)]
pub struct HttpRequestRequestLine {
    method: HttpRequestMethod,
    /// This is a work around to store the Url as the request_target, as the library `url::Url` does not allow relative urls parsing.
    /// It is build with the domain, protocol in the config file and port under env.
    ///
    /// `NOTE`: No information is read from `request_target` other than it's path, changes to protocol are only made to
    /// avoid ambiguity in code. `request_target` is only read with a getter, that performs proper parsing.
    request_target: url::Url,
    protocol: HttpProtocol,
}

impl<'a> HttpRequestRequestLine {
    pub async fn new(
        config: &MutexGuard<'_, Config>,
        line: &'a str,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let fields = line.split_whitespace().collect::<Vec<&'a str>>();

        if fields.len() != 3 {
            return Err(HttpRequestError {
                status_code: 400,
                status_text: String::from("Bad Request"),
                internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
                    "Request line is malformed, possibly request_target did not encode the separator: {}",
                    line
                ))),
                ..Default::default()
            }
            .into());
        }

        let [method, request_target, protocol] = fields
            .get(0..3)
            .ok_or(HttpRequestError {
                status_code: 400,
                status_text: String::from("Bad Request"),
                internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
                    "Request line is malformed: {}",
                    line
                ))),
                ..Default::default()
            })?
            .try_into()
            .map_err(|e| HttpRequestError {
                status_code: 400,
                status_text: String::from("Bad Request"),
                internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
                    "Error converting slice to array: {}",
                    e
                ))),
                ..Default::default()
            })?;

        // The idea there is to use the url::Url lib, but it does not allow building relative URL's so we will use
        // absolute one but with a default's for domain, port and protocol under Config file for safety.
        // We want the functionality for setting path segments and queries so we have to do that.

        let base = config.app.url.clone();

        // Remove leading root identifier from the request_target as that would end up redundant and invalid
        // The reason is doing parsing with url::Url you will end up with a double root after clearing the segments
        // and setting the new path segments.
        // NOTE: The segments actually does not exists in the url that does come with the config.http_url
        // that is just for being overly cautious (look at this man, what you taking about, you and cautions...).

        // Check if request target is a valid URL.
        if let Ok(_) = url::Url::parse(request_target) {
            return Err(HttpRequestError {
                status_code: 400,
                status_text: String::from("Bad Request"),
                internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
                    "request target was sent as an URL: {}",
                    request_target
                ))),
                ..Default::default()
            }
            .into());
        }

        // take the path portion of the request_target
        // we have to do that as in the query part those symbols could not be considered invalid all the time,
        // for example if we want to sent query to search for something, we should not be limited
        // what we could search for.

        // We are working on non-percent-decoded request_target so save to assume that "?" is a separator for queries.
        let path = request_target.split('?').next().unwrap_or(request_target);

        HttpRequestHeaders::validate_request_target_path(path).map_err(|internals| {
            Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                status_code: 400,
                status_text: "Bad Request".into(),
                message: "Corrupted request target".to_string().into(),
                internals: Some(internals),
                ..Default::default()
            })
        })?;

        let mut request_target = base.join(request_target).map_err(|e| HttpRequestError {
            status_code: 400,
            status_text: String::from("Bad Request"),
            message: Some(format!("Invalid request target: {}", request_target)),
            internals: Some(Box::<dyn Error + Send + Sync>::from(e)),
            ..Default::default()
        })?;

        let protocol: HttpProtocol = HttpProtocol::from_str(protocol)?;

        request_target
            .set_scheme(protocol.simplify())
            .map_err(|_| HttpRequestError {
                status_code: 400,
                status_text: String::from("Bad Request"),
                message: Some(format!("Invalid request target: {}", request_target)),
                internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
                    "Could not change scheme on request_target: {} | scheme: {}",
                    request_target, protocol
                ))),
                ..Default::default()
            })?;

        Ok(Self {
            method: HttpRequestMethod::from_str(method)?,
            request_target,
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

    // pub(super) fn get_request_target_mut(&mut self) -> &mut url::Url {
    //     &mut self.request_target
    // }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash, strum_macros::EnumIter, PartialOrd, Ord)]
pub enum HttpRequestMethod {
    GET,
    POST,
    DELETE,
    // PATCH and PUT will be equivalent to each other.
    PATCH,
    PUT,
}

impl Display for HttpRequestMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub struct HttpResponseStartLine<'a> {
    protocol: HttpProtocol,
    // status_code should be typed for all available status codes
    status_code: u16,
    status_text: Option<&'a str>,
}

impl Default for HttpResponseStartLine<'_> {
    fn default() -> Self {
        Self {
            protocol: HttpProtocol::HTTP1_1,
            status_code: 200,
            status_text: Some("OK"),
        }
    }
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

#[derive(Debug, Serialize, Deserialize)]
/// `status_code` and `status_text` are specific to the HTTP protocol, specifically the start line of HTTP message
/// `content_type` is used to return appropriate response to the client
/// `message` is used to inform the user about the error, not standardized in HTTP
pub struct HttpRequestError {
    pub status_code: u16,
    /// Standardized description of an error, technically should be optional.
    /// NOTE: If we would have an enum of the status_code's we could map the status_text to each of the said status codes.
    pub status_text: String,
    /// Used to describe in what format the response is sent to the client.
    pub content_type: Option<String>,
    /// Is used to give context of an error that is sent to the client, not strictly to be displayed always.
    /// It should not contain any sensitive information, but that is implicit as it gets redirected to the client.
    pub message: Option<String>,
    /// For logging purposes, used to redirect some errors to up the stack to avoid repetitive printing on server
    /// while returning the error to the client. Should not be exposed to the client. Is skipped during serialization.
    #[serde(skip)]
    pub internals: Option<Box<dyn Error + Send + Sync>>,
}

impl Default for HttpRequestError {
    fn default() -> Self {
        Self {
            status_code: 500,
            status_text: String::from("Internal Server Error"),
            content_type: Some(String::from("text/html")),
            message: Some("An error occurred while processing a request".to_string()),
            internals: None,
        }
    }
}
impl Display for HttpRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "http/error: {}: {} ({})",
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

#[derive(Debug)]
/// Used as a sentinel to indicate to control the flow of the request handling.
/// When request gets redirected, the response is sent to the client,
/// the previous writer is shutdown and the request handling is stopped via error propagation.
///
pub struct RequestRedirected;

impl std::fmt::Display for RequestRedirected {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Request was redirected and response was sent, writer was shutdown."
        )
    }
}

impl std::error::Error for RequestRedirected {}

impl HttpRequestError {
    /// NOTE: Can log anything that implements `std::fmt::Display`
    ///
    /// Logs request or response that come from the client or response from the server to ./log.txt

    /// Sends error response to the client, based on the error that occurred during request handling
    /// downcasting to the specific error type from `Box<dyn Error + Send + Sync` and handling it accordingly
    ///
    /// If stream is None,
    /// If err is None, send default 500 Internal Server Error response
    ///
    /// NOTE: Default error message can be send by setting `err` to HttpRequestError::default()
    pub async fn send_error_response(
        config: Arc<Mutex<Config>>,
        writer: Arc<Mutex<OwnedWriteHalf>>,
        // writer: &mut OwnedWriteHalf,
        // stream: &mut MutexGuard<'_, OwnedWriteHalf>,
        err: Box<dyn Error + Send + Sync>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // NOTE: This page could be dynamically set, but this function is sketchy and not very useful and flexible, so maybe we will refactor in the future.

        dbg!(&err);
        
        let mut writer = writer.lock().await;
        let config = config.lock().await;

        let (mut body, mut headers): (Option<String>, Option<HttpResponseHeaders>) = (None, None);

        if let Some(http_err) = err.as_ref().downcast_ref::<HttpRequestError>() {
            let error_page = Config::get_server_public().join("pages/error.html");

            let start_line = HttpResponseStartLine::new(
                HttpProtocol::HTTP1_1,
                http_err.status_code,
                &http_err.status_text,
            );

            headers = Some(HttpResponseHeaders::new(start_line));

            body = Some(match &http_err.content_type {
                Some(content_type) if content_type == "application/json" => {
                    // This basically sends the `struct` stringified as JSON
                    serde_json::to_string(http_err)?
                }
                Some(content_type) if content_type == "text/plain" => {
                    // Keep in mind that the message also has its default value set in Default impl,
                    // so the other branch would evaluate only if explicitly set to None,

                    // Excerpt => message: Some("An error occurred while processing a request".to_string()),

                    if let Some(message) = &http_err.message {
                        message.clone()
                    } else {
                        format!("{:#?}", http_err)
                    }
                }
                // NOTE: matching different content-types
                // Some(content_type) if content_type == "application/x-www-form-urlencoded"
                // Otherwise sending HTML error page as a response
                _ => std::fs::read_to_string(error_page)?,
            });

            // Setting default content-type as text/html
            headers.as_mut().unwrap().add(
                Cow::from("Content-Type"),
                Cow::from(
                    http_err
                        .content_type
                        .clone()
                        .unwrap_or(String::from("text/html")),
                ),
            );

            let headers = headers.unwrap();
            let mut response = HttpResponse::new(&headers, body);

            return response.write(&config, &mut writer).await;
        }
        // This is used to control the flow of the program, not really an error.
        // It is used to early return from the request parsing when the Host header is invalid or is configured for an redirection
        // It also allows us to not check for the error message in the request handling code, currently the entry point is the `handle_client` function.
        // and we just propagate the error up the stack if any occurs.
        else if let Some(sentinel_redirection) = err.as_ref().downcast_ref::<RequestRedirected>()
        {
            eprintln!("Sentinel redirection: {}", sentinel_redirection);

            return Ok(());
        }

        eprintln!("Error while responding: {}", err);

        if let Some(mut headers) = headers {
            // Error message can have no body, for some status codes
            // the body is forbidden.
            if let Some(body) = body.as_ref() {
                headers.add(
                    Cow::from("Content-Length"),
                    Cow::from(body.len().to_string()),
                );
            }

            let mut response = HttpResponse::new(&headers, body);

            return response.write(&config, &mut writer).await;
        } else {
            // If there is no headers and body we cannot sent full custom response, as without it
            // it is just a malformed response. We will return a base error response.
            // It is also a case if the error is not of specific type where we know how to handle it
            // We won't expose that error to the client.

            headers = Some(HttpResponseHeaders::new(HttpResponseStartLine::new(
                HttpProtocol::HTTP1_1,
                500,
                "Internal Server Error",
            )));

            headers
                .as_mut()
                .unwrap()
                .add(Cow::from("Content-Type"), Cow::from("text/plain"));

            body = Some(String::from("An error occurred while processing a request"));

            headers.as_mut().unwrap().add(
                Cow::from("Content-Length"),
                Cow::from(body.as_ref().unwrap().len().to_string()),
            );

            let headers = headers.unwrap();
            let mut response = HttpResponse::new(&headers, body);

            return response.write(&config, &mut writer).await;
        }
    }
}

impl FromStr for HttpRequestMethod {
    type Err = HttpRequestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "GET" => Ok(HttpRequestMethod::GET),
            "POST" => Ok(HttpRequestMethod::POST),
            "DELETE" => Ok(HttpRequestMethod::DELETE),
            "PATCH" => Ok(HttpRequestMethod::PATCH),
            "PUT" => Ok(HttpRequestMethod::PUT),
            _ => Err(HttpRequestError {
                status_code: 501,
                status_text: String::from("Not Implemented"),
                ..Default::default()
            }),
        }
    }
}

/// Accesses headers field of the struct
pub trait HttpHeaders<'a> {
    fn get_headers(&'a self) -> &'a HashMap<Cow<'a, str>, Cow<'a, str>>;

    /// Accesses headers field of the struct mutably
    fn get_headers_mut(&mut self) -> &mut HashMap<Cow<'a, str>, Cow<'a, str>>;

    /// Access header by key
    fn get(&'a self, key: &'a str) -> Option<&'a Cow<'a, str>> {
        self.get_headers().get(key)
    }

    /// That avoids overhead of implementing Iterator specifically for that struct, so for iteration use `iter()` method
    fn iter(&'a self) -> std::collections::hash_map::Iter<'a, Cow<'a, str>, Cow<'a, str>> {
        self.get_headers().iter()
    }

    /// That avoids overhead of implementing Iterator specifically for that struct, so for iteration use `iter_mut()` method
    fn iter_mut(
        &'a mut self,
    ) -> std::collections::hash_map::IterMut<'a, Cow<'a, str>, Cow<'a, str>> {
        self.get_headers_mut().iter_mut()
    }

    /// Here's the docs: https://datatracker.ietf.org/doc/html/rfc2616#section-14
    ///
    /// Suck on this <Writes on a rock, SASSY office reference>
    /// Default impl uses `headers_mut()`
    fn add(&mut self, key: Cow<'a, str>, value: Cow<'a, str>) {
        self.get_headers_mut().insert(key, value);
    }

    /// Parses String formatted as key-value pair delimited by ": ", validating the correctness
    fn add_header_line(&mut self, line: String) {
        let [key, value]: [String; 2] = line
            .split(": ")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .try_into()
            .expect("Incorrect header. Request is malformed.");

        self.add(key.into(), value.into());
    }
}

#[derive(Debug)]
pub struct HttpRequestHeaders<'a> {
    headers: HeaderMap<'a>,
    request_line: HttpRequestRequestLine,
}

impl<'a> HttpHeaders<'a> for HttpRequestHeaders<'a> {
    fn get_headers(&'a self) -> &'a HashMap<Cow<'a, str>, Cow<'a, str>> {
        let header_map = &self.headers;
        &header_map.headers
    }

    fn get_headers_mut(&mut self) -> &mut HashMap<Cow<'a, str>, Cow<'a, str>> {
        &mut self.headers.headers
    }
}

impl<'a> HttpRequestHeaders<'a> {
    pub fn new(request_line: HttpRequestRequestLine) -> HttpRequestHeaders<'a> {
        HttpRequestHeaders {
            headers: HeaderMap::new(),
            request_line,
        }
    }

    /// `Works on encoded request_target`
    ///
    /// Invalidates request target if it contains file system traversal symbols, `./` | `../` or consecutive slashes
    /// (slashes that do not contain a path segment in between them) that are given as literals or encoded in percent-encoding.
    ///
    /// `NOTE`: Percent encoded slashes or any of the characters that could affect system path resolution,
    /// should not affect the actual file system path resolution, user should not be able to encode
    /// path characters, even thought after validation that would be valid if decoded.
    ///
    /// We need to stop decoding slashes and backslashes or disallow them in the request target
    ///
    /// We will not allow encoded slashes or backslashes in the request target.
    ///
    /// We will not allow consecutive slashes, but because of the former we just need
    /// to consider literal slashes not the encoded ones.
    pub fn validate_request_target_path(
        request_target: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if request_target.is_empty() {
            return Err(Box::<dyn Error + Send + Sync>::from(
                "Request target cannot be empty",
            ));
        }

        // Edge case: Encoded separators would also be invalid if given as a filename or directory name,

        // File system traversal symbols
        const RELATIVE_TO_PATH_SYMBOL: &str = "./";
        const RELATIVE_TO_PATH_SYMBOL_2: &str = ".\\";
        const ONE_DIRECTORY_DOWN_SYMBOL_2: &str = "..\\";
        const ONE_DIRECTORY_DOWN_SYMBOL: &str = "../";
        const PERCENT_ENCODED_DOT: &str = "%2E";

        // Percent encoded slashes, that would be invalid in the request target
        const PERCENT_ENCODED_SLASH: &str = "%2F";
        const PERCENT_ENCODED_BACKSLASH: &str = "%5C";
        const DOUBLE_SLASH: &str = "//";
        const DOUBLE_BACKSLASH: &str = "\\\\";

        const DISALLOWED_SYMBOLS: [&str; 9] = [
            RELATIVE_TO_PATH_SYMBOL,
            RELATIVE_TO_PATH_SYMBOL_2,
            ONE_DIRECTORY_DOWN_SYMBOL,
            ONE_DIRECTORY_DOWN_SYMBOL_2,
            PERCENT_ENCODED_DOT,
            PERCENT_ENCODED_SLASH,
            PERCENT_ENCODED_BACKSLASH,
            DOUBLE_SLASH,
            DOUBLE_BACKSLASH,
        ];

        let request_target = request_target.to_lowercase();

        // NOTE: In the future we could think about rewriting request if consecutive slashes are found.
        // Behavior for encoded slashes will not change thought.

        if DISALLOWED_SYMBOLS
            .iter()
            .any(|symbol| request_target.contains(&symbol.to_lowercase()))
        {
            return Err(Box::<dyn Error + Send + Sync>::from(format!(
                "File system traversal symbols or consecutive slashes {}",
                request_target
            )));
        }

        Ok(())
    }

    // NOTE: I think the below getters could be migrated to HttpResponse as the field that it accesses
    // gets exposed to `super` context, either way it is surely visible out there.

    pub fn get_request_line(&self) -> &HttpRequestRequestLine {
        &self.request_line
    }

    pub fn get_method(&self) -> &HttpRequestMethod {
        self.get_request_line().get_method()
    }

    pub fn get_request_target(&self) -> &url::Url {
        self.get_request_line().get_request_target()
    }

    pub fn normalize_path(path: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        let path = path.replace('\\', "/");

        let mut path = if path != "/" {
            path.strip_prefix("/").unwrap_or(&path)
        } else {
            path.as_ref()
        };

        for dir in SpecialDirectories::iter() {
            let dir = dir.to_string();

            // We are not stripping the assets as files in that directory do not map to the specific extension.
            if dir == SpecialDirectories::Assets.to_string() {
                continue;
            }

            // Path cannot be of special directory
            if path == dir {
                return Err(Box::<dyn Error + Send + Sync>::from(format!(
                    "Request target path cannot be of special directory: {}",
                    dir
                )));
            }
            // If the path starts with the special directory, we strip it
            else if let Some(p) = path.strip_prefix(&format!("{}/", dir.to_string())) {
                path = p;
                break;
            }
        }

        // Resolve the server index path to root that is mapped in the router.
        if path == Config::SERVER_INDEX_PATH {
            path = "/"
        }

        Ok(String::from(path))
    }

    /// Maps specialized directories based on the file extension of the requested path.
    ///
    /// - If the requested file ends with `.html`, we look in the `/public/pages` directory.
    /// - If it ends with `.css`, we look in the `/public/styles` directory.
    ///
    /// This mapping assumes the request path ends with an extension. If it doesn't:
    ///
    /// - If the `requested_path` does **not** contain a file extension in the final segment, we treat it as a directory.
    /// - In that case, we try to find an `index.html` inside that directory.
    /// - However, we also check if the path might point to a file **without** an extension. If it is a file, we cannot determine its type.
    ///
    /// If the extension doesn't match any of our specialized mappings:
    ///
    /// - We fall back to joining the path with the `/public` directory and check for a matching file or directory.
    ///
    /// **Important:**  
    /// If the path points to a file **without an extension**, we cannot determine the file type and will throw an error,
    /// as we do not support serving unknown types.
    ///
    /// ## Design Note
    ///
    /// - We only support `index.html` as a default file for directories.
    /// - Specialized directories like `/pages` and `/styles` will **not** resolve to default files.
    pub fn prefix_path(path: &str) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
        let path = Self::normalize_path(path)?;

        if path == "/" {
            return Ok(PathBuf::from(format!(
                "{}/{}",
                SpecialDirectories::Pages.to_string(),
                Config::SERVER_INDEX_PATH
            )));
        }

        let mut normalized = PathBuf::from(path);

        let p = match normalized.extension() {
            Some(ext) => {
                let dir_path = SpecialDirectories::resolve_path(ext);

                match dir_path {
                    Some(dir) => {
                        let filename = normalized.file_stem().ok_or_else(|| {
                            Box::<dyn Error + Send + Sync>::from(format!(
                                "Failed to extract file stem from path: {:?}",
                                normalized
                            ))
                        })?;
                        if (normalized.starts_with(&dir) && filename == dir)
                            || normalized.starts_with(&dir)
                        {
                            // Already prefixed, do nothing
                            Ok(normalized)
                        } else {
                            Ok(dir.join(normalized))
                        }
                    }
                    None => Ok(normalized),
                }
            }
            None => {
                let mut dir = PathBuf::from(SpecialDirectories::Pages.to_string());

                normalized.push("index.html");

                dir.push(normalized);
                Ok(dir)
            }
        };

        p
    }

    /// Returns the request target path, which is the path portion of the request target URL.
    ///
    /// Decodes the path and stripes the leading slash if present. Replaces backslashes with slashes
    pub fn get_request_target_path(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
        // NOTE: This basically reverts the normalization.
        let path = self.get_request_target().path();

        let path = Self::normalize_path(path).map_err(|e| {
            Box::<dyn Error + Send + Sync>::from(format!(
                "Could not normalize the path from the client: {}",
                e
            ))
        })?;

        let decoded = percent_encoding::percent_decode_str(path.as_ref())
            .decode_utf8()?
            .to_string();

        // make it case insensitive
        return Ok(decoded.to_lowercase());
    }

    pub fn get_request_protocol(&self) -> &HttpProtocol {
        self.get_request_line().get_protocol()
    }
}

#[derive(Debug)]
pub struct HeaderMap<'a> {
    headers: HashMap<Cow<'a, str>, Cow<'a, str>>,
}

impl<'a> HeaderMap<'a> {
    fn new() -> HeaderMap<'a> {
        HeaderMap {
            headers: HashMap::<Cow<str>, Cow<str>>::new(),
        }
    }
}

#[derive(Debug)]
pub struct HttpResponseHeaders<'a> {
    headers: HeaderMap<'a>,
    start_line: HttpResponseStartLine<'a>,
}

impl<'a> HttpHeaders<'a> for HttpResponseHeaders<'a> {
    fn get_headers(&'a self) -> &'a HashMap<Cow<'a, str>, Cow<'a, str>> {
        let header_map = &self.headers;
        &header_map.headers
    }

    fn get_headers_mut(&mut self) -> &mut HashMap<Cow<'a, str>, Cow<'a, str>> {
        &mut self.headers.headers
    }
}

impl<'a> HttpResponseHeaders<'a> {
    pub fn new(start_line: HttpResponseStartLine<'a>) -> HttpResponseHeaders<'a> {
        HttpResponseHeaders {
            headers: HeaderMap::new(),
            start_line,
        }
    }

    // NOTE: I think the below getters could be migrated to HttpResponse as the field that it accesses
    // gets exposed to `super` context, either way it is surely visible out there.

    pub fn get_start_line(&self) -> &HttpResponseStartLine {
        &self.start_line
    }

    pub fn get_status_code(&self) -> u16 {
        self.get_start_line().get_status_code()
    }

    // NOTE: Should stay Optional as the status text is not mandatory in the response
    // and may be removed in the future as that is some kind of shenanigans being honest.
    pub fn get_status_text(&self) -> Option<&str> {
        self.get_start_line().get_status_text()
    }

    pub fn get_response_protocol(&self) -> &HttpProtocol {
        self.get_start_line().get_protocol()
    }
}
