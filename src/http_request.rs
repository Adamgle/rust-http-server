use std::borrow::Cow;
use std::error::Error;
use std::f32::consts::E;
use std::io::{BufRead, BufReader, Read};
use std::path::{PathBuf, PrefixComponent};
use std::sync::{Arc, Mutex};
use std::task::Context;
use std::time::Duration;
use std::{fs, thread};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::Config;

use crate::{
    http::{
        HttpHeaders, HttpProtocol, HttpRequestError, HttpRequestMethod, HttpRequestRequestLine,
        HttpResponseStartLine,
    },
    http_response::HttpResponse,
};

#[derive(Debug)]
pub struct HttpRequest<'a> {
    // headers: String,
    parsed_headers: HttpHeaders<'a>,
    body: Option<Vec<u8>>,
}

impl<'a> std::fmt::Display for HttpRequest<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:#?}\n{:#?}",
            self.parsed_headers,
            "" // self.body.clone().map(|v| String::from_utf8(v))
        )
    }
}
impl<'a> HttpRequest<'a> {
    // Creates new HttpRequest instance from TcpStream, reads the stream to UTF-8 String and parses the headers
    pub async fn new(config: &mut Config, stream: &mut TcpStream) -> Result<Self, Box<dyn Error>> {
        // Parse the TCP stream
        let (parsed_headers, body) = Self::parse_request(config, stream).await?;

        Ok(Self {
            // headers,
            parsed_headers,
            body,
        })
    }

    async fn parse_request(
        config: &mut Config,
        stream: &mut TcpStream,
    ) -> Result<(HttpHeaders<'a>, Option<Vec<u8>>), Box<dyn Error>> {
        let mut buffer = Vec::<u8>::new();

        // Stable solution
        // 1. We will look for Content-Length header, we should get it in one read
        // thought it does not really matter. Content-Length header is the size of the message in bytes
        // incomplete message is an indication of a bad request and should be terminated.
        // 2.

        // TODO: Maybe it could greater idea to encapsulate that data as something like HttpRequestParser or other name
        // because it feels kind of static or unstructured
        let mut expected_size: Option<usize> = None;
        let mut headers: Option<HttpHeaders> = None;
        let mut transferred: usize = 0;

        'outer: loop {
            if let Some(expected_size) = expected_size {
                if transferred == expected_size {
                    break;
                }
            }

            stream.readable().await?;

            let mut chunk = [0u8; 1024];

            match stream.try_read(&mut chunk) {
                Ok(0) => break,
                Ok(bytes_read) => {
                    // expected_size is set only if we have encountered the end of the headers, meaning empty line or CRLF
                    if expected_size.is_some() {
                        buffer.extend_from_slice(&chunk[..bytes_read]);
                        transferred += bytes_read;
                        continue;
                    }

                    let lines = chunk[..bytes_read].as_ref().lines();

                    'inner: for (idx, line) in lines.enumerate() {
                        match line {
                            Ok(line) => {
                                // If line is empty, we have reached the end of the headers
                                // At this point Content-length should arrive, if in the headers we have the content-length
                                // header, then we should expect the body after empty line, based on that we will make a decision,
                                // even if there is content-length. the message transmitted up to that line could be completed
                                // if the content-length is equal to the size of the buffer, meaning body sent is empty

                                if line.is_empty() {
                                    // This should be evaluated only on POST, PUT, UPDATE/PATCH
                                    if let Some(content_length) =
                                        headers.as_ref().unwrap().get("Content-Length")
                                    {
                                        // If content-length is 0, we should not expect any body
                                        if content_length == "0" {
                                            break 'outer;
                                        }

                                        expected_size = (content_length
                                            .parse::<usize>()
                                            .expect("Could not parse size")
                                            + transferred as usize)
                                            .into();

                                        // That could be unstable, off by one possible
                                        let body_pos = transferred + (idx + 1) * 2;

                                        // Flush the rest the buffer regardless if there is a content or not

                                        buffer.extend_from_slice(&chunk[body_pos..bytes_read]);

                                        // NOTE: Could be off by one, not sure
                                        transferred += bytes_read - body_pos;

                                        break 'inner;
                                    } else {
                                        // If there is no content-length header, we should not expect any body
                                        // request parsed
                                        break 'outer;
                                    }
                                } else {
                                    transferred += line.len();

                                    // First line is request line
                                    if headers.is_none() {
                                        headers = Some(Self::new_headers(
                                            HttpRequestRequestLine::new(config, &line)
                                                .expect("Request line is invalid"),
                                        ));
                                    } else {
                                        headers
                                            .as_mut()
                                            .expect("Headers are not initialized")
                                            .add_header_line(line);
                                    }
                                }
                            }
                            Err(e) => panic!("Error reading line from stream: {}", e),
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(err) => {
                    eprintln!("Error reading from stream: {}", err);

                    return Err(Box::new(HttpRequestError {
                        status_code: 400,
                        status_text: String::from("Bad Request"),
                        ..Default::default()
                    }));
                }
            }
        }

        if let Some(headers) = headers {
            Ok((headers, Some(buffer)))
        } else {
            // NOTE: This probably useless, the shutdown
            stream.shutdown().await?;
            return Err("Invalid request".into());
        }
    }

    pub fn get_body(&self) -> Option<&Vec<u8>> {
        self.body.as_ref()
    }

    fn new_headers(request_line: HttpRequestRequestLine) -> HttpHeaders<'a> {
        // NOTE: I guess this is bad design, because we are creating the fields of the struct positionally
        HttpHeaders::new(None, request_line.into())
    }

    pub fn get_method(&self) -> &HttpRequestMethod {
        self.parsed_headers.get_method().unwrap()
    }

    /// Returns absolute path to the requested resource on the server
    ///
    /// Checks for existence of the path, return 404 if path does not exists
    pub fn get_absolute_resource_path(&self) -> Result<PathBuf, HttpRequestError> {
        // request_line is guaranteed to be Some
        let target = self.parsed_headers.get_request_target().unwrap();

        target.canonicalize().map_err(|e| {
            eprintln!("Path not found: {:?}\nWith error message {}", target, e);

            HttpRequestError {
                status_code: 404,
                status_text: String::from("Not Found"),
                ..Default::default()
            }
        })
    }

    /// Returns relative path to the requested resource
    ///
    /// Checks for existence of the path, return 404 if path does not exists
    pub fn get_path_segment(&self, config: &mut Config) -> Result<PathBuf, HttpRequestError> {
        // I do not like that idea because printing requesting: <path> would be misleading, showing "/" instead of actual path resource
        // which on the server is consistency is important
        // you could mitigate that by creating a structure that implements Display with alternate behavior
        // TODO: Normalize the `dir`/index.html to '/' root

        let absolute_path = self.get_absolute_resource_path()?;

        absolute_path
            .strip_prefix(Config::get_server_public())
            .map(|p| match p {
                // If path is root, return index.html
                p if p == &config.get_index_path() => "/".into(),
                p => p.into(),
            })
            // Should not happen ever because that would be equivalent to accessing a server files outside of the public directory
            .map_err(|e| {
                eprintln!(
                    "Requested path is not a prefix of the server public path: {:?}",
                    e
                );

                HttpRequestError {
                    status_code: 404,
                    status_text: String::from("Not Found"),
                    ..Default::default()
                }
            })
    }

    /// Takes Response `HttpHeaders` and write `Content-Type` and `Content-Length` headers, returning the requested resource as a String
    /// Walks `/public` directory looking for path
    pub fn read_requested_resource(
        &'a self,
        // request: &'a HttpHeaders<'a>,
        response_headers: &mut HttpHeaders<'a>,
    ) -> Result<String, Box<dyn Error>> {
        let resource_path = self.get_absolute_resource_path()?;

        // Read the file
        let requested_resource = fs::read_to_string(resource_path)?;

        response_headers.add(
            Cow::from("Content-Length"),
            Cow::from(requested_resource.len().to_string()),
        );

        response_headers.add(
            Cow::from("Content-Type"),
            Cow::from(self.parsed_headers.detect_mime_type()),
        );

        return Ok(requested_resource);
    }

    /// This function is not meant to work as a redirection to specified URL
    /// Instead we will configure paths that should be redirected
    ///
    /// Configuration is derived from `config/config.json`
    ///
    /// Return bool indicating if the request was redirected
    pub async fn redirect_request(
        &self,
        stream: &mut TcpStream,
        config: &mut Config,
    ) -> Result<bool, Box<dyn Error>> {
        for (key, value) in self.parsed_headers.get_headers() {
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

                                    let start_line = HttpResponseStartLine::new(
                                        HttpProtocol::HTTP1_1,
                                        // May have to be changed to 307
                                        308,
                                        "Permanent Redirect",
                                    )
                                    .into();

                                    let mut response_headers =
                                        HttpResponse::new_headers(start_line);

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

                                    location
                                        .set_path(self.get_path_segment(config)?.to_str().unwrap());

                                    // NOTE: This as it happens can be relative, so we could try to make it relative someday
                                    response_headers
                                        .add("Location".into(), location.to_string().into());

                                    response_headers
                                        .add(Cow::from("Content-Length"), Cow::from("0"));

                                    println!("Redirecting to: {location}");

                                    let mut response: HttpResponse<'_> =
                                        HttpResponse::new(response_headers, None)?;

                                    response.write(config, stream).await?;

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

        Ok(false)
    }
}
