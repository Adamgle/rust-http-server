use crate::config::Config;
use crate::http::{HttpResponseHeaders, RequestRedirected};

use std::borrow::Cow;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::timeout;

use crate::prelude::*;

use crate::{
    http::{HttpProtocol, HttpRequestError, HttpRequestRequestLine, HttpResponseStartLine},
    http_response::HttpResponse,
};

use super::{HttpHeaders, HttpRequestHeaders, HttpRequestMethod};

#[derive(Debug)]
pub struct HttpRequest<'a> {
    // headers: String,
    headers: HttpRequestHeaders<'a>,
    body: Option<Vec<u8>>,
}

impl<'a> std::fmt::Display for HttpRequest<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}\n{:#?}", self.headers, "")
    }
}

impl<'a> HttpRequest<'a> {
    /// Creates new HttpRequest instance from TcpStream, reads the stream to UTF-8 String and parses the headers
    ///
    /// `NOTE`: This could return an error if the request was redirect of: `"Request was redirected, writer was shutdown"`
    pub async fn new(
        config: &MutexGuard<'_, Config>,
        reader: &mut OwnedReadHalf,
        writer: &mut MutexGuard<'_, OwnedWriteHalf>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self::parse_request(config, reader, writer).await?)
    }

    /// Parses to HTTP/1.1 from the TcpStream, relying on Content-Length headers, no chunked transfer encoding
    /// is supported. It will read the stream and allocate as much as Content-Length header specifies.
    async fn parse_request(
        config: &MutexGuard<'_, Config>,
        reader: &mut OwnedReadHalf,
        writer: &mut MutexGuard<'_, OwnedWriteHalf>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // TODO: There is still and issue with the TCP-Keep-Alive packets, currently they are non-blocking,
        // and quickly aborted by the timeout or by the irruption from another task.

        // NOTE: There could be a potential buffer overflow here, if the request is too large for server to handle.

        // Could be None if TcpStream is not valid HTTP message.
        let mut headers: Option<HttpRequestHeaders> = None;

        // NOTE: Stream will not become readable for TCP-Keep-Alive packet.
        // The writer would be shutdown upstream when error occurs, inside the
        timeout(Duration::from_secs(5), reader.readable())
            .await
            .inspect_err(|e| {
                eprintln!("Error waiting for the stream to be readable: {:?}", e);
            })??;

        let reader = BufReader::new(reader);
        let mut lines = reader.lines();

        let mut host_validated = false;

        while let Some(line) = lines.next_line().await.inspect_err(|e| {
            eprintln!("Error reading line from the stream: {}", e);
        })? {
            if line.is_empty() {
                if headers.is_some() {
                    // Empty line means end of headers
                    break;
                } else {
                    // If headers are not initialized, that means we have not read the request line yet
                    return Err(Box::from(HttpRequestError {
                        status_code: 400,
                        status_text: "Bad Request".into(),
                        message: "Invalid request".to_string().into(),
                        internals: Some(Box::<dyn Error + Send + Sync>::from(
                            "Empty line in the request before reading the request line.",
                        )),
                        ..Default::default()
                    }));
                }
            } else if headers.is_none() {
                // First line is request line
                headers = Some(HttpRequestHeaders::new(
                    HttpRequestRequestLine::new(&config, &line).await?,
                ));
            } else {
                // Error should not happen if the http message is semantically correct
                // NOTE: ok_or_else will never happen because of the else if above

                headers
                    .as_mut()
                    .ok_or_else(|| HttpRequestError {
                        status_code: 400,
                        status_text: "Bad Request".into(),
                        message: "Invalid request".to_string().into(),
                        internals: Some(Box::<dyn Error + Send + Sync>::from(
                            "Headers are not initialized while parsing header from line.",
                        )),
                        ..Default::default()
                    })?
                    .add_header_line(line);
            }

            // Look for Host header, to validate it's correctness, try to redirect the request
            if let Some((headers, Some(host))) = headers.as_ref().map(|h| (h, h.get("Host"))) {
                // If the Host header is not present, we will not redirect the request
                // First try to redirect the request if the Host header is present
                // We are doing it first as we would fall in the endless loop if we would check for host
                // header being wrong, then redirecting to the other host header which could also end up wrong
                // and so on. This approach is correct under the assumption that we will redirect to the valid domain
                // given in the configuration file.

                // Someday we could if we would want to support redirection to multiple domains
                // `redirect_request` would have to either return a iterator over the domains to redirect to
                // and if something matches that we would just redirect to that one, or we could do that based on the geolocation
                // of the user location to redirect to the closest domain

                match host_validated {
                    true => {
                        // Host header was already validated, do not validate it again

                        let domain = &config.config_file.domain;
                        let port = Config::get_server_port();

                        if host.to_string() != format!("{}:{}", domain, port) {
                            return Err(Box::from(HttpRequestError {
                                status_code: 400,
                                status_text: "Bad Request".into(),
                                message: "Invalid request".to_string().into(),
                                internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
                                    "Invalid Host header: {}",
                                    host
                                ))),
                                ..Default::default()
                            }));
                        }
                    }
                    false => {
                        // Validate the Host header against the configuration file
                        // First =>  run the redirection logic to check if we should redirect early
                        // that would work for any redirection that is configured and is done while
                        // first processing the request
                        // Second => validate the Host header against the configured domain
                        // If the Host header is not valid, we will return an error
                        // Third => If the Host header is valid, we will continue processing the request

                        // If the host is not valid, return an error
                        // If the host is valid, continue processing the request

                        // The redirection logic may seem ambiguous, because we are doing it before
                        // validating the domain, but either way we would have to do it, so we have to run it
                        // before the Host header validation to not just return an error if it is invalid
                        // but also redirect if we should. But really the order of the checks does not matter.

                        let is_redirected = Self::redirect_request(
                            config,
                            &headers,
                            writer,
                            &headers.get_request_target_path()?,
                        )
                        .await?;

                        if is_redirected {
                            // The only way we want to pass the information about the redirection without explicitly sending some flag
                            // that it was redirected is to return error from the function as it would propagate up the call stack
                            // the propagation would end the request that was redirected and the writer was already utilized to write the response,
                            // any checks about reading the requested resource would be pointless or could be malicious as we would operate on the invalid Host header

                            // To make sure the previous request will be surely aborted and even if we forget
                            // about the error propagation, we will still be unable to use the previous request
                            // by closing also the reader portion of the stream.
                            // Writer is being closed in the `redirect_request` function, so we do not have to worry about that.
                            // UPDATE: We cant close the reading portion of the stream as that is not specified in TCP.

                            // Send a sentinel error to indicate that the request was redirected
                            return Err(Box::from(RequestRedirected));
                        }

                        host_validated = true;
                    }
                }
            }
        }

        // Read the rest of the stream, if any
        // Body of the request will only be present if the request method is POST, PUT, PATCH
        // and when the Content-Length header is present in the headers

        let mut body_buffer: Option<Vec<u8>> = None;

        if let Some(headers) = headers {
            if let Some(content_length) = headers.get("Content-Length") {
                let content_length = content_length.parse::<usize>().inspect_err(|e| {
                    eprintln!("Could not parse the Content-Length header as a valid integer: {e}")
                })?;

                if content_length != 0 {
                    // Initialize the buffer only when there will be data to read
                    body_buffer = Some(Vec::with_capacity(content_length));

                    let mut transferred: usize = 0;
                    let mut reader = lines.into_inner();

                    // No data loss is acceptable
                    while transferred != content_length {
                        let chunk = reader.fill_buf().await?;

                        // What if there is no data on the wire while reading, but it will be?
                        if chunk.is_empty() {
                            break;
                        }

                        // unwrap is safe there
                        body_buffer.as_mut().unwrap().extend_from_slice(chunk);

                        let bytes_read = chunk.len();
                        reader.consume(bytes_read);
                        transferred += bytes_read;
                        // println!("Transferred: {}/{}", transferred, content_length);
                    }
                }
            };

            return Ok(Self {
                body: body_buffer,
                headers,
            });
        } else {
            // TCP_keepalive

            eprintln!("Headers are not initialized");
            return Err("Invalid request".into());
        }
    }

    pub fn get_body(&self) -> Option<&Vec<u8>> {
        self.body.as_ref()
    }

    pub fn get_method(&self) -> &HttpRequestMethod {
        &self.headers.get_method()
    }

    pub fn get_headers(&self) -> &HttpRequestHeaders {
        &self.headers
    }

    // pub fn get_request_line(&self) -> Option<&HttpRequestRequestLine> {}

    /// Returns absolute path to the requested resource on the server
    ///
    /// Resolves '/' to '/pages/index.html'
    ///
    /// Checks for existence of the path, return error if the path does not exists
    ///
    /// `NOTE`: We will not support matching paths without extensions for now.
    /// Last segment without extension will be treated as a directory and we will try to find `index.html` in that directory
    ///
    /// `NOTE`: Paths `/pages/index.html` and `/index.html` and "/" are valid paths that point to `/pages` directory on `index.html` file.
    ///
    /// `TODO`: Query parsing is not implemented
    pub fn get_absolute_resource_path(
        &self,
        // config: &MutexGuard<'_, Config>,
    ) -> Result<PathBuf, HttpRequestError> {
        match self.get_request_target_path() {
            Ok(path) => {
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

                // println!("Path in get_absolute_resource_path: {:?}", path);

                let public = Config::get_server_public();

                // If that would be absolute and would join with the public directory path, it would create a new absolute path
                // effectively allowing to traverse the file system of the server

                // I do not know if that is stable enough, as windows has weird absolute path handling

                let path = PathBuf::from(path);

                // NOTE: The second condition looks weird.
                // On Windows, a path is absolute if it has a prefix and starts with the root: c:\windows is absolute, while c:temp and !!! \temp !!! are not.

                if path.is_absolute()
                    || ((path.starts_with("/") || path.starts_with("\\")) && path.is_relative())
                {
                    eprintln!("Path is absolute, not allowed: {:?}", path);
                    return Err(HttpRequestError {
                        status_code: 400,
                        status_text: "Bad Request".into(),
                        message: "Corrupted path".to_string().into(),
                        // NOTE: I do not understand why this is declared as an owned String
                        ..Default::default()
                    });
                };

                // Routing to /pages, /styles, /client is undefined behavior, as those paths are not accessible by the client directly

                let path = if path.is_relative() {
                    public.join(path)
                } else {
                    path
                };

                match path.try_exists() {
                    Ok(true) if path.starts_with(public) => Ok(path),
                    _ => Err(HttpRequestError {
                        status_code: 400,
                        status_text: "Bad Request".into(),
                        message: "Invalid request target".to_string().into(),
                        internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
                            "Path does not start with the public directory : {:?}",
                            path
                        ))),
                        ..Default::default()
                    }),
                }
            }
            Err(err) => {
                return Err(HttpRequestError {
                    status_code: 400,
                    status_text: "Bad Request".into(),
                    internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
                        "Could not decode the path as UTF-8: {}",
                        err
                    ))),
                    ..Default::default()
                });
            }
        }
    }

    /// Returns Iterator over the query parameters of the request target, presumably percent-encoded.
    pub fn get_request_target_query(&self) -> url::form_urlencoded::Parse<'_> {
        self.headers.get_request_target().query_pairs()
    }

    /// Wrapper around `HttpHeaders::get_request_target_path` just to hoist the logic into `HttpRequest` struct.
    /// Returns path of the requested resource without resolving "/" to "pages/index.html"
    ///
    /// Decoding the percent-encoded path to UTF-8
    pub fn get_request_target_path(&self) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
        self.headers.get_request_target_path()
    }
    // Makes a GET request to the server, returning the requested resource as a String
    ///
    /// Takes Response `HttpHeaders` and write `Content-Type` and `Content-Length` headers, returning the requested resource as a String
    ///
    /// Walks `/public` directory looking for path, actually it is O(1) lookup.
    ///
    /// `relative_path` is already resolved path, fully valid if prefixed with `/public` directory.
    pub fn read_requested_resource(
        &'a self,
        headers: &mut HttpResponseHeaders<'a>,
        relative_path: &PathBuf,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let resource_path: PathBuf = Config::get_server_public().join(relative_path);

        // Read the file
        let requested_resource = fs::read_to_string(resource_path)?;

        headers.add(
            Cow::from("Content-Length"),
            Cow::from(requested_resource.len().to_string()),
        );

        headers.add(
            Cow::from("Content-Type"),
            Cow::from(self.detect_mime_type(relative_path)),
        );

        return Ok(requested_resource);
    }

    /// I hate this, should be typed
    pub fn detect_mime_type(&self, request_target: &PathBuf) -> &str {
        match self.headers.get("Content-Type") {
            Some(content_type) => return content_type,
            None => {
                // At this point file name should always be supplied as this path resolves root directories to index.html and so on.
                // Given that, expect would be appropriate as that would be just the server error1.

                // NOTE: There could be problem with the casing.
                let actual_file = Path::new(
                    request_target
                        .file_name()
                        .expect("Request target does not point to a file."),
                );

                // Shenanigans, foolishness
                match actual_file.extension() {
                    Some(extension) => {
                        // NOTE: That is controversial string conversion
                        return match extension
                            .to_str()
                            .expect("Extension is not UTF-8 compatible")
                        {
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

    /// This function is NOT meant to work as a redirection to specified URL
    /// Instead we will configure paths that should be redirected
    ///
    /// Configuration is derived from `~/config/config.json`
    ///
    /// Return bool indicating if the request was redirected
    pub async fn redirect_request(
        // &self,
        config: &MutexGuard<'_, Config>,
        headers: &HttpRequestHeaders<'a>,
        writer: &mut MutexGuard<'_, OwnedWriteHalf>,
        // writer: &mut MutexGuard<'_, OwnedWriteHalf>,
        path: &PathBuf,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        // NOTE: Indentation in this function are f'ed up, should be fixed

        // Redirection is done based on config file deps under redirect/domains declared
        // as the Vector of RedirectDomainEntry structs

        // for (key, value) in self.get_headers() {
        if let Some(host) = headers.get("Host") {
            if let Some(Some(domains)) = config.config_file.redirect.as_ref().map(|r| &r.domains) {
                // NOTE: That Would make sens if the domains would be a HashMap, domain.from would be key and domain.to a value
                // although maybe we would want to have single domain redirect to multiple domains eg. based on location
                // but of course that is reaching and we won't do that type of redirection. Also redirection like that would be preferably
                // done based on different header.
                for domain in domains {
                    if host.to_string() == domain.from {
                        // Write 301 Moved Permanently || 308 Permanent Redirect to the stream, supply the Location header
                        // We will use 308

                        let start_line = HttpResponseStartLine::new(
                            HttpProtocol::HTTP1_1,
                            308,
                            "Permanent Redirect",
                        )
                        .into();

                        let mut headers = HttpResponseHeaders::new(start_line);

                        // NOTE: What if domain is invalid and the path is invalid
                        // then we would have to redirect both. That is we need path variable to be passed

                        // NOTE: Macro for writing headers would be great
                        let mut location = config.config_file.domain_to_url(
                            &domain.to,
                            &Config::get_server_port().parse::<u16>().map_err(|e| {
                                HttpRequestError {
                                    internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
                                        "Could not parse server port, not valid u16: {}",
                                        e
                                    ))),
                                    ..Default::default()
                                }
                            })?,
                        )?;

                        // Could be problems if the path is not valid UTF-8
                        let path = path.to_string_lossy();

                        println!("Redirecting from: {} | {}", domain.from, path);
                        println!("Redirecting to: {} | {}", location, path);

                        location.set_path(path.as_ref());

                        // NOTE: This as it happens can be relative, so we could try to make it relative someday
                        headers.add("Location".into(), location.to_string().into());

                        headers.add(Cow::from("Content-Length"), Cow::from("0"));

                        let mut response: HttpResponse<'_> = HttpResponse::new(&headers, None);

                        response.write(config, writer).await?;

                        writer.shutdown().await?;

                        return Ok(true);
                    }
                }
            }
            // _ => (),
        }
        // }

        Ok(false)
    }
}
