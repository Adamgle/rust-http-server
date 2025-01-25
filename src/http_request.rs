use std::borrow::Cow;
use std::error::Error;
use std::fs;
use std::net::TcpStream;
use std::path::PathBuf;

use crate::config::Config;

use crate::http::{
    HttpHeaders, HttpProtocol, HttpRequestError, HttpRequestMethod, HttpRequestRequestLine,
    HttpResponseStartLine,
};

use crate::http_response::HttpResponse;
use crate::tcp_handlers::read_tcp_stream;

pub struct HttpRequest<'a> {
    headers: String,
    parsed_headers: HttpHeaders<'a>,
    body: Option<String>,
}

impl<'a> HttpRequest<'a> {
    // Creates new HttpRequest instance from TcpStream, reads the stream to UTF-8 String and parses the headers
    pub fn new(config: &Config, stream: &mut TcpStream) -> Result<Self, Box<dyn Error>> {
        // Parse the TCP stream
        let headers = read_tcp_stream(stream)?;
        let (parsed_headers, body) = Self::parse_headers(config, headers.clone())?;

        Ok(Self {
            headers,
            parsed_headers,
            body,
        })
    }

    // Parses headers from the String, returns HttpHeaders and optional body that comes with request
    // We know that `headers` is non empty stream read from TCPStream, UTF-8 encoded
    fn parse_headers(
        config: &Config,
        headers: String,
    ) -> Result<(HttpHeaders<'a>, Option<String>), Box<dyn Error>> {
        // Ignore the CRLF at both ends of headers

        let mut headers_iter = headers.trim().lines();

        let request_line: HttpRequestRequestLine = HttpRequestRequestLine::new(
            config,
            headers_iter.next().expect("Request line not found").trim(),
        )?;

        let method = request_line.get_method().clone();

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
                    println!("INFO: body part of the request is empty")
                }

                break;
            }

            let entry = header.split(": ").collect::<Vec<_>>();

            let (key, value) = entry
                .get(0..2)
                .map(|entry| (entry[0].to_string(), entry[1].to_string()))
                // Termination there
                .ok_or_else(|| {
                    eprintln!("Header not in the correct format: {:?}", entry);
                    HttpRequestError {
                        status_code: 400,
                        status_text: String::from("Bad Request"),
                        ..Default::default()
                    }
                })?;

            parsed_headers.add(Cow::from(key), Cow::from(value));
        }

        return Ok((parsed_headers, body));
    }

    pub fn get_body(&self) -> Option<&String> {
        self.body.as_ref()
    }

    fn new_headers(request_line: HttpRequestRequestLine) -> HttpHeaders<'a> {
        // NOTE: I guess this is bad design, because we are creating the fields of the struct positionally
        HttpHeaders::new(None, request_line.into())
    }

    pub fn get_method(&self) -> &HttpRequestMethod {
        self.parsed_headers
            .get_request_line()
            .as_ref()
            .unwrap()
            .get_method()
    }

    /// Returns absolute path to the requested resource on the server
    ///
    /// Checks for existence of the path, return 404 if path does not exists
    pub fn get_absolute_resource_path(&self) -> Result<PathBuf, HttpRequestError> {
        // request_line is guaranteed to be Some
        let target = self
            .parsed_headers
            .get_request_line()
            .unwrap()
            .get_request_target();

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
    pub fn get_path_segment(&self, config: &Config) -> Result<PathBuf, HttpRequestError> {
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
    pub fn redirect_request(
        &self,
        stream: &mut TcpStream,
        config: &'a Config,
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

        Ok(false)
    }
}
