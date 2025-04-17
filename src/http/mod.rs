pub mod http_request;
pub mod http_response;

use crate::{config::Config, http_response::HttpResponse};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow, collections::HashMap, error::Error, fmt::Display, str::FromStr,
};
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
                eprintln!("Error converting slice to array: {}", e);
                HttpRequestError {
                    status_code: 400,
                    status_text: String::from("Bad Request"),
                    ..Default::default()
                }
            })?;

        // The idea there is to use the url::Url lib, but it does not allow building relative URL's so we will use
        // absolute one but with a default's for domain, port and protocol under Config file for safety.
        // We want the functionality for setting path segments and queries so we have to do that.

        let mut host = config.http_url.clone();

        // Remove leading root identifier from the request_target as that would end up redundant and invalid
        // The reason is doing parsing with url::Url you will end up with a double root after clearing the segments
        // and setting the new path segments.
        // NOTE: The segments actually does not exists in the url that does come with the config.http_url
        // that is just for being overly cautious (look at this man, what you taking about, you and cautions...).

        let request_target = request_target.strip_prefix("/").unwrap_or(&request_target);

        host.path_segments_mut()
            .map_err(|_| {
                eprintln!("Error getting mutable segments of request_target");
                HttpRequestError::default()
            })
            .map(|mut segments| {
                segments.clear();
                segments.push(request_target);
            })?;

        let protocol: HttpProtocol = HttpProtocol::from_str(protocol)?;

        host.set_scheme(protocol.simplify()).map_err(|_| {
            eprintln!("Error setting scheme to the request_target");
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

    // pub(super) fn get_request_target_mut(&mut self) -> &mut url::Url {
    //     &mut self.request_target
    // }
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
        config: &MutexGuard<'_, Config>,
        stream: &mut MutexGuard<'_, OwnedWriteHalf>,
        err: Box<dyn Error + Send + Sync>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // NOTE: This page could be dynamically set, but this function is sketchy and not very useful and flexible, so maybe we will refactor in the future.

        if let Some(http_err) = err.as_ref().downcast_ref::<HttpRequestError>() {
            eprintln!("Error while responding: {:?}", http_err);
            let error_page = Config::get_server_public().join("pages/error.html");

            let start_line = HttpResponseStartLine::new(
                HttpProtocol::HTTP1_1,
                http_err.status_code,
                &http_err.status_text,
            );

            let mut headers = HttpResponseHeaders::new(start_line);

            let body = match &http_err.content_type {
                Some(content_type) if content_type == "application/json" => {
                    serde_json::to_string(http_err)?
                }
                Some(content_type) if content_type == "text/plain" => {
                    format!("{:#?}", http_err)
                }
                // NOTE: matching different content-types
                // Some(content_type) if content_type == "application/x-www-form-urlencoded"
                _ => std::fs::read_to_string(error_page)?,
            };

            // Setting default content-type as text/html
            headers.add(
                Cow::from("Content-Type"),
                Cow::from(
                    http_err
                        .content_type
                        .clone()
                        .unwrap_or(String::from("text/html")),
                ),
            );

            headers.add(
                Cow::from("Content-Length"),
                Cow::from(body.len().to_string()),
            );

            let mut response = HttpResponse::new(headers, Some(body));
            return response.write(&config, stream).await;
        } else {
            // Sending text/plain as the error message if the error is not of the HttpRequestError type
            eprintln!("Error while responding: {:?}", err);

            let mut headers = HttpResponseHeaders::new(HttpResponseStartLine::new(
                HttpProtocol::HTTP1_1,
                500,
                "Internal Server Error",
            ));

            headers.add(Cow::from("Content-Type"), Cow::from("text/plain"));

            // err cannot expose any sensitive information, but that is implicit as it gets redirected to the client.
            let body = format!("An error occurred while processing a request: {:#?}", err);

            headers.add(
                Cow::from("Content-Length"),
                Cow::from(body.len().to_string()),
            );

            let mut response = HttpResponse::new(headers, Some(body));

            return response.write(&config, stream).await;
        }
        // NOTE: This is how you can handle different errors by downcasting to the specific error type
        // else if let Some(io_err) = err.downcast_ref::<std::io::Error>() {}
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
