use crate::config::Config;

use std::borrow::Cow;
use std::error::Error;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::str::Utf8Error;
use std::{fs, vec};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::prelude::*;

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
        write!(f, "{:#?}\n{:#?}", self.parsed_headers, "")
    }
}
impl<'a> HttpRequest<'a> {
    // Creates new HttpRequest instance from TcpStream, reads the stream to UTF-8 String and parses the headers
    pub async fn new(
        config: &MutexGuard<'_, Config>,
        stream: &mut TcpStream,
    ) -> Result<Self, Box<dyn Error>> {
        // Parse the TCP stream
        let (mut parsed_headers, body) = Self::parse_request(&config, stream).await?;

        // NOTE: I thing the discrepancy between the domain used here should be resolved thought should be investigated first
        // requested_target => http://localhost:5000/ It uses config to build the url as the default from the domain and port
        //  -> thought if the request is made from different domain, first off all it is not possible,
        //  -> Host: 127.0.0.1:5000 => request_target => localhost:5000 
        // NOTE: Something like this should be done
        
        if let Some(request_line) = parsed_headers.get_request_target_mut() {
            // if let Some(domain) = request_line.domain() {
            //     *request_line.set_host()
            // }   
            // println!("request_line: {:?}", request_line.as_str());

            // let domain = &config.config_file.domain.clone();

            // request_line.set_host(Some(domain)).unwrap();

            // println!("After setting host: {:?}", request_line.as_str());
        }

        Ok(Self {
            // headers,
            parsed_headers,
            body,
        })
    }

    /// Parses http request from the TcpStream
    async fn parse_request(
        config: &MutexGuard<'_, Config>,
        stream: &mut TcpStream,
    ) -> Result<(HttpHeaders<'a>, Option<Vec<u8>>), Box<dyn Error>> {
        // TODO: Verify the presence of the Host header, 400 if not present

        let mut buffer = Vec::<u8>::new();

        // Stable solution
        // 1. We will look for Content-Length header, we should get it in one read
        // thought it does not really matter. Content-Length header is the size of the message in bytes
        // incomplete message is an indication of a bad request and should be terminated.

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

            // NOTE: There could be an issue if the headers are larger than 1024 bytes
            // that could omit some bytes because they will appear as not CRLF terminated
            // because full line was not read

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
                                            HttpRequestRequestLine::new(&config, &line)
                                                .await
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
            stream.shutdown().await?;

            return Err("Invalid request".into());
        }
    }

    pub fn get_body(&self) -> Option<&Vec<u8>> {
        self.body.as_ref()
    }

    fn new_headers(request_line: HttpRequestRequestLine) -> HttpHeaders<'a> {
        HttpHeaders::new(None, request_line.into())
    }

    pub fn get_method(&self) -> &HttpRequestMethod {
        self.parsed_headers.get_method().unwrap()
    }

    /// Returns absolute path to the requested resource on the server
    ///
    /// Resolves '/' to '/index.html'
    ///
    /// Checks for existence of the path, return 404 if path does not exists
    ///
    /// `NOTE`: WE will not support matching paths without extensions for now
    /// last segment without extension will be treated as a directory and we will try to find index.html in that directory
    pub fn get_absolute_resource_path(
        &self,
        config: &MutexGuard<'_, Config>,
    ) -> Result<PathBuf, HttpRequestError> {
        match self
            .get_request_target_path()
            // NOTE: We could mutate the segments directly
        {
            Ok(path) => {
                // TODO: In order to match the files on the server you need to look up specialized directories
                // in the /public, in order to do that you could do as follows:

                // 1. We know that the file in 99% cases does not exists at given path, thought it could be in the specialized directories 
                // we could simply traverse the /public directory in order to find a file, so given path:
                // .../public/index.html => We would look at every directory in order to find out that it was under pages directory
                // this solution is not optimal, but would fulfill every case, thought this does not utilize the fact of the existence of specialized directories
                
                // 2. We will map specialized directories to the extension of the file requested, so if the file is requested with .html extension
                // we will look in the /public/pages directory, if the file is requested with .css extension we will look in the /public/styles directory
                // thought that solution cannot predict the requested path if it does not end with an extension that would resolve to appropriate directory
                // In that case, if the requested_path does not contain a file extension as the last segment, we would treat that as a directory,
                // thought we have to check if it is not a file without an extension, and then we would try to find index.html in that directory.

                // If that would be absolute and would join with the public directory path, it would create a new absolute path
                // effectively allowing to traverse the file system of the server
                
                let path = path.to_string();
                
                // NOTE: Error handling should be done here
                let path = Path::new(&path).strip_prefix("/").expect("Invalid path");

                // I do not know if that is stable enough, as windows has weird absolute path handling
                if path.is_absolute() || path.starts_with("/") {
                    eprintln!("Path is absolute, not allowed: {:?}", path);
                    return Err(HttpRequestError {
                        status_code: 400,
                        status_text: "Bad Request".into(),
                        // NOTE: I do not understand why this is declared as an owned String
                        content_type: String::from("application/json").into(),
                        ..Default::default()
                    });
                };

                let path = Config::get_server_public().join(path);
                println!("Path with segments: {:?}", path);

                // This checks file existence
                let metadata = path.metadata().map_err(|err| {
                    eprintln!("[ERROR MESSAGE]: {err}");
                    HttpRequestError::default()
                })?;

                if metadata.is_dir() {
                    // Check if index.html exists in the directory
                    let index_path = path.join("index.html");

                    if index_path.exists() {
                        return Ok(index_path);
                    }
                } else {
                    // It's a file
                    // Check if the file has a extension, as those without are not supported, that would require some bytes-based checking
                    if path.extension().is_some() {
                        return Ok(path);
                    }
                }

                Err(HttpRequestError::default())
            }
            Err(err) => {
                eprintln!("Could not decode the path as UTF-8: {}", err);

                return Err(HttpRequestError {
                    status_code: 400,
                    status_text: "Bad Request".into(),
                    ..Default::default()
                });
            }
        }
    }

    /// Returns path of the requested resource without resolving "/" to "index.html"
    /// Encoding the percent-encoded path to UTF-8
    // NOTE: Consider making it eagerly unwrapped as this is critical for request to continue
    pub fn get_request_target_path(&self) -> Result<Cow<'_, str>, Utf8Error> {
        percent_encoding::percent_decode(
            self.parsed_headers
                .get_request_target()
                .map(|s: &url::Url| s.path())
                .unwrap()
                .as_bytes(),
        )
        .decode_utf8()
    }

    /// Returns relative path to the requested resource on the server, without resolving "/" to "index.html".
    /// Relies on self.get_path_segments() to get the path segments as a Vector<&str>
    /// `Example`
    ///
    /// Given path segments ["/"] would evaluate to "/"
    ///
    /// Given path segments ["path", "to", "dir", ""] would evaluate to "/path/to/dir/"
    ///
    /// Given path segments ["path", "to", "dir"] would evaluate to "/path/to/dir" \\ NOTE: Dir should be treated a directory, and we will
    ///                                                                            \\ try to find index.html in that directory
    // NOTE: Consider making it eagerly unwrapped as this is critical for request to continue
    // pub fn get_path_segment(&self) -> Option<String> {
    //     self.get_path_segments().map(|segments| segments.join("/"))
    // }

    /// Takes Response `HttpHeaders` and write `Content-Type` and `Content-Length` headers, returning the requested resource as a String
    /// Walks `/public` directory looking for path
    pub fn read_requested_resource(
        &'a self,
        config: &MutexGuard<'_, Config>,
        response_headers: &mut HttpHeaders<'a>,
    ) -> Result<String, Box<dyn Error>> {
        let resource_path: PathBuf = self.get_absolute_resource_path(config)?;
        println!("resource_path: {:?}", resource_path);

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
        config: &MutexGuard<'_, Config>,
        stream: &mut TcpStream,
        path: &Cow<'_, str>,
    ) -> Result<bool, Box<dyn Error>> {
        // NOTE: Indentation in this function are f'ed up, should be fixed
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
                                    // like database/tasks.json we should set the location header
                                    // not only to the domain but also suffix it with the incoming path
                                    // for request to be valid and correctly redirected

                                    // NOTE: What if domain is invalid and the path is invalid
                                    // then we would have to redirect both.

                                    // NOTE: Macro for writing headers would be great
                                    let mut location =
                                        config.config_file.domain_to_url(&domain.to)?;

                                    // NOTE: Headers should be refactored to separate structs for Response and Request,
                                    // as this ads the ambiguity of path segment to be None which is impossible
                                    // and cannot be set as an normal Type because in the Response headers it would be None
                                    // and in the given approach we always have to check for it to be Some
                                    // UPDATE: Not really, see todo.txt

                                    location.set_path(path);

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
