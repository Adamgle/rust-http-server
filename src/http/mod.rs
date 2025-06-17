pub mod http_request;
pub mod http_response;

use crate::config::SpecialDirectories;
use crate::prelude::*;
use crate::{config::Config, http_response::HttpResponse};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::{borrow::Cow, collections::HashMap, error::Error, fmt::Display, str::FromStr};
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

        let base = config.http_url.clone();

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

        let path = request_target.split('?').next().unwrap_or(request_target);
        HttpRequestHeaders::validate_request_target_path(path.to_string())?;

        let mut request_target = base
            // .strip_prefix("/").unwrap_or(&request_target)
            .join(request_target)
            .map_err(|e| HttpRequestError {
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

#[derive(Debug, PartialEq, Clone, Eq, Hash, PartialEq)]
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
            message: None,
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
                    format!("{:#?}", http_err)
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

            let mut response = HttpResponse::new(headers.unwrap(), body);
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

            let mut response = HttpResponse::new(headers, body);

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

            let mut response = HttpResponse::new(headers.unwrap(), body);

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

    /// Invalidates request target if it contains file system traversal symbols, `./` | `../` or consecutive slashes
    /// (slashes the do not contain a path segment in between them).
    ///
    /// NOTE: This validating function creates some limitations for the request target, that could technically be valid paths
    /// but due to my negligence I will keep it this way. Path with encoded slashes are not supported, so any file encoding
    /// "/" or "\", eg. "asd/asd%2Fasd" would evaluate to whole different path: "asd/asd/asd", we want to avoid that,
    /// so we will not support it. Also I cannot think of way to decode something like a space but do not decode the slash,
    /// and when to do so.
    /// `NOTE`: This should be run on un-decoded request target path.
    pub fn validate_request_target_path(
        request_target: String,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        const RELATIVE_TO_PATH_SYMBOL: &str = "./";
        const ONE_DIRECTORY_DOWN_SYMBOL: &str = "../";
        // Equivalent using backslash.
        const ONE_DIRECTORY_DOWN_SYMBOL_2: &str = "..\\";
        const RELATIVE_TO_PATH_SYMBOL_2: &str = ".\\";
        const PERCENT_ENCODED_SLASH: &str = "%2F";
        const PERCENT_ENCODED_BACKSLASH: &str = "%5C";

        let mut is_prev_slash = false;

        for (idx, symbol) in request_target.to_string().chars().enumerate() {
            let window_2 = request_target.get(idx..idx + 2).unwrap_or_default();
            let window_3 = request_target.get(idx..idx + 3).unwrap_or_default();

            if window_2 == RELATIVE_TO_PATH_SYMBOL
                || window_2 == RELATIVE_TO_PATH_SYMBOL_2
                || window_3 == ONE_DIRECTORY_DOWN_SYMBOL
                || window_3 == ONE_DIRECTORY_DOWN_SYMBOL_2
                || window_3 == PERCENT_ENCODED_BACKSLASH
                || window_3 == PERCENT_ENCODED_SLASH
                || ((symbol == '/' || symbol == '\\') && is_prev_slash)
            {
                return Err(HttpRequestError {
                    status_code: 400,
                    status_text: "Bad Request".into(),
                    message: "Corrupted request target".to_string().into(),
                    internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
                        "Path contains file system traversal symbols or consecutive slashes {}",
                        request_target
                    ))),
                    ..Default::default()
                }
                .into());
            }

            if symbol == '/' || symbol == '\\' {
                is_prev_slash = true;
            } else {
                is_prev_slash = false;
            }
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

    // `NOTE`: That method is also hoisted to `HttpRequest`
    pub fn get_request_target_path(&self) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
        // We will map specialized directories to the extension of the file requested, so if the file is requested with .html extension
        // we will look in the /public/pages directory, if the file is requested with .css extension we will look in the /public/styles directory
        // thought that solution cannot predict the requested path if it does not end with an extension that would resolve to appropriate directory
        // In that case, if the requested_path does not contain a file extension as the last segment, we would treat that as a directory,
        // thought we have to check if it is not a file without an extension, and then we would try to find index.html in that directory.

        // If file extension does not fall into the mapping, we would just traverse the directory, joining the path to the public directory
        // and try to match an existing path.
        // If the path does point to a file and has no extension, there is not way in current approach to detect
        // it's type, we will throw an error in that case as we cannot know the type of the file and we cannot serve it.

        // DESIGN NOTE: We will support default files of the directories in the path, only index.html as the default. Other specialized directories will not
        // try to resolve any paths when not given with full filename.

        let path = self.get_request_target().path();
        let path = match path.strip_prefix("/") {
            // Case of the root requested: "/"
            // Some(stripped_path) if stripped_path.is_empty() => path,
            Some(stripped_path) => stripped_path,
            None => path,
        };

        let decoded = percent_encoding::percent_decode_str(path).decode_utf8()?;

        // That would validate the decoded port of the path of the URL, leaving query parameters untouched.
        // This create an ambiguity as it would invalidate slashes given as literal, in percent encoded form,
        // maybe we should opt out of that behavior as that would make some path names invalid
        // that contain the encoded slash, which they are technically valid.
        // HttpRequestHeaders::validate_request_target(decoded.to_string())?;

        // NOTE: That may a breaking change so need to watch it closely, currently in the path
        // there is leading slash and I want to remove it. Maybe that will no broke anything as
        // we either way removing that slash when reading the resource.

        // I think we may safely convert it to path as that is not absolute path as it lacks the leading slash.
        let mut path = PathBuf::from(decoded.as_ref());

        // println!("path: {:?}", path);

        if path != Path::new("/")
            && (path.is_absolute()
                || path.starts_with("/")
                || path.starts_with("\\")
                || path.has_root())
        {
            return Err(HttpRequestError {
                status_code: 400,
                status_text: "Bad Request".into(),
                message: "Invalid request target".to_string().into(),
                content_type: "text/html".to_string().into(),
                internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
                    "Request target path is absolute, but should be relative: {:?}",
                    path
                ))),
                ..Default::default()
            }
            .into());
        }

        let path = match path.extension() {
            Some(ext) => {
                let dir_path = SpecialDirectories::resolve_path(ext).and_then(|f| {
                    Some((
                        f.clone(),
                        PathBuf::from_str(f.as_str())
                            .inspect_err(|f| {
                                eprintln!(
                                    "Could not convert the special directory to PathBuf: {}",
                                    f
                                );
                            })
                            .ok(),
                    ))
                });

                match dir_path {
                    Some((dir, Some(mut dir_path))) => {
                        // Handle cases where the path is already prefixed with the directory
                        // considering the filenames that are of the name of specialized directories

                        // File stem is a portion of the file name before the last dot
                        // Technically that file_prefix would be more appropriate but that is nightly only
                        //
                        // assert_eq!("foo", Path::new("foo.rs").file_stem().unwrap());
                        // assert_eq!("foo.tar", Path::new("foo.tar.gz").file_stem().unwrap());

                        let filename = path
                            .file_stem()
                            .ok_or(HttpRequestError {
                                status_code: 400,
                                status_text: "Bad Request".into(),
                                message: "Invalid request target".to_string().into(),
                                content_type: "text/html".to_string().into(),
                                internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
                                    "File stem does not exists in the path: {:?}",
                                    path
                                ))),
                                ..Default::default()
                            })
                            .map(|s| {
                                s.to_str().ok_or(HttpRequestError {
                                    status_code: 400,
                                    status_text: "Bad Request".into(),
                                    message: "Invalid request target".to_string().into(),
                                    content_type: "text/html".to_string().into(),
                                    internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
                                        "Could not convert the path as valid UTF-8 string: {:?}",
                                        path
                                    ))),
                                    ..Default::default()
                                })
                            })??;

                        if (path.starts_with(&dir) && filename == &dir) || path.starts_with(dir) {
                            // Case of: /pages/pages.html not prefixing
                            // Case of: /pages/...

                            // Do not prefix that
                            // public.join(path)
                            path
                        } else {
                            // Things like: /pages.html are prefixing

                            // Do prefix that

                            dir_path.push(path);
                            dir_path
                            // &Path::new(&dir).join(path)
                        }
                    }
                    // There is not specialized directory for the extension or parsing the extension to UTF-8 failed, do not care
                    _ => path,
                }
            }
            None => {
                // Treat it as a directory
                // If file extension does not fall into the mapping, we would lookup that in the directory, joining the path to the public directory
                // and try to match an existing path. If the path does point to a file or has no extension, there is not way in current approach to detect
                // it's format, we will throw an error in that case as we cannot know the format of the file and we cannot serve it.
                // The same if the path points to a directory

                // What happens: /dir => /pages/dir/index.html
                // That also prefixes the root "/" to "/pages/index.html"
                let mut dir = PathBuf::from(SpecialDirectories::Pages.to_string().as_str());

                path.push("index.html");
                dir.push(path.clone());

                dir
            }
        };

        // let path_str = path.to_str().ok_or(HttpRequestError {
        //     status_code: 400,
        //     status_text: "Bad Request".into(),
        //     message: "Invalid request target".to_string().into(),
        //     content_type: "text/html".to_string().into(),
        //     internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
        //         "Could not convert the path as valid UTF-8 string: {:?}",
        //         path
        //     ))),
        //     ..Default::default()
        // })?;

        // println!("Request target path: {:?}", path);

        return Ok(path);
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
