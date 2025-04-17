use crate::config::Config;
use crate::http::HttpResponseHeaders;

use std::borrow::Cow;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::Utf8Error;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
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
    // Creates new HttpRequest instance from TcpStream, reads the stream to UTF-8 String and parses the headers
    pub async fn new(
        config: &MutexGuard<'_, Config>,
        stream: &mut OwnedReadHalf,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Parse the TCP stream

        Ok(Self::parse_request(config, stream).await?)
    }

    /// Parses http request from the TcpStream
    async fn parse_request(
        config: &MutexGuard<'_, Config>,
        stream: &mut OwnedReadHalf,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // ONGOING FIXES

        // TODO: Verify the presence of the Host header, 400 if not present
        // Also make the headers validation as there is none at the moment, not only the Host header.

        // Could be None if TcpStream is not valid HTTP message.
        let mut headers: Option<HttpRequestHeaders> = None;

        // NOTE: Stream will not become readable for TCP-Keep-Alive packet.
        timeout(Duration::from_secs(0), stream.readable())
            .await
            .inspect_err(|e| {
                eprintln!("Error waiting for the stream to be readable: {:?}", e);
            })??;

        let reader = BufReader::new(stream);
        let mut lines = reader.lines();

        while let Some(line) = lines.next_line().await.inspect_err(|e| {
            eprintln!("Error reading line from the stream: {}", e);
        })? {
            if line.is_empty() {
                break;
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
                    .ok_or_else(|| {
                        eprintln!("Headers are not initialized while parsing header from line.");
                        "Invalid request"
                    })?
                    .add_header_line(line);
            }
        }

        // Read the rest of the stream, if any
        // Body of the request will only be present if the request method is POST, PUT, UPDATE/PATCH
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
        match self.get_request_target() {
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

                let public = Config::get_server_public();

                let path: String = path.to_string();

                // NOTE: Error handling should be done here
                let path = Path::new(&path).strip_prefix("/").expect("Invalid path");

                // If that would be absolute and would join with the public directory path, it would create a new absolute path
                // effectively allowing to traverse the file system of the server

                // I do not know if that is stable enough, as windows has weird absolute path handling

                if path.is_absolute() || path.starts_with("/") && path.is_relative() {
                    eprintln!("Path is absolute, not allowed: {:?}", path);
                    return Err(HttpRequestError {
                        status_code: 400,
                        status_text: "Bad Request".into(),
                        // NOTE: I do not understand why this is declared as an owned String
                        content_type: String::from("application/json").into(),
                        ..Default::default()
                    });
                };

                // Routing to /pages, /styles, /client is undefined behavior, as those paths are not accessible by the client directly

                match path.extension() {
                    Some(ext) => {
                        let dir = ext
                            .to_str()
                            .map(|ext| match ext {
                                // NOTE: pages, styles, and client should not be String, enum for those should be declared
                                "html" => Some("pages"),
                                "css" => Some("styles"),
                                "js" => Some("client"),
                                _ => None,
                            })
                            .flatten();

                        let path = match dir {
                            Some(dir) => {
                                // Handle cases where the path is already prefixed with the directory
                                // considering the filenames that are of the name of specialized directories

                                if (path.starts_with(dir)
                                    && path.file_stem().unwrap().to_str().unwrap() == dir)
                                    || path.starts_with(dir)
                                {
                                    // Case of: /pages/pages.html not prefixing
                                    // Case of: /pages/...

                                    // Do not prefix that
                                    public.join(path)
                                } else {
                                    // Things like: /pages.html are prefixing

                                    // Do prefix that
                                    public.join(dir).join(path)
                                }
                            }
                            // There is not specialized directory for the extension or parsing the extension to UTF-8 failed, do not care
                            None => public.join(path),
                        };

                        if path.exists() {
                            return Ok(path);
                        }
                    }
                    None => {
                        // Treat it as a directory
                        // If file extension does not fall into the mapping, we would just traverse the directory, joining the path to the public directory
                        // and try to match an existing path. If the path does point to a file or has no extension, there is not way in current approach to detect
                        // it's format, we will throw an error in that case as we cannot know the format of the file and we cannot serve it.
                        // The same if the path points to a directory

                        // What happens: /dir => /pages/dir/index.html
                        let path = public.join("pages").join(path.join("index.html"));

                        if let Ok(exists) = path.try_exists() {
                            if exists {
                                return Ok(path);
                            }
                        }
                    }
                };

                return Err(HttpRequestError::default());
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
    ///
    /// Decoding the percent-encoded path to UTF-8
    // NOTE: Consider making it eagerly unwrapped as this is critical for request to continue
    pub fn get_request_target(&self) -> Result<Cow<'_, str>, Utf8Error> {
        percent_encoding::percent_decode(
            self.headers
                .get_request_target()
                .path()
                // TODO: Think about improving the error handling there
                // .expect("Invalid request target, does not follow a scheme of a path.")
                .as_bytes(),
        )
        .decode_utf8()
    }

    /// Takes Response `HttpHeaders` and write `Content-Type` and `Content-Length` headers, returning the requested resource as a String
    ///
    /// Walks `/public` directory looking for path
    /// NOTE: Not sure about the lifetimes there
    pub fn read_requested_resource(
        &'a self,
        headers: &mut HttpResponseHeaders<'a>,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let resource_path: PathBuf = self.get_absolute_resource_path()?;

        let relative_path = resource_path
            .strip_prefix(Config::get_server_public())
            .expect("Server public directory is not a prefix of the requested resource")
            // clone there
            .to_owned();

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
    pub fn detect_mime_type(&self, request_target: PathBuf) -> &str {
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
        &self,
        config: &MutexGuard<'_, Config>,
        stream: &mut MutexGuard<'_, OwnedWriteHalf>,
        path: &Cow<'_, str>,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        // NOTE: Indentation in this function are f'ed up, should be fixed
        // NOTE: This function is very stupid, it iterates over HashMap instead using O(1) lookup

        // Redirection is done based on config file deps under redirect/domains declared
        // as the Vector of RedirectDomainEntry structs

        // for (key, value) in self.get_headers() {
        if let Some(host) = self.headers.get("Host") {
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
                        // then we would have to redirect both.

                        // NOTE: Macro for writing headers would be great
                        let mut location = config.config_file.domain_to_url(&domain.to)?;

                        // NOTE: Headers should be refactored to separate structs for Response and Request,
                        // as this ads the ambiguity of path segment to be None which is impossible
                        // and cannot be set as an normal Type because in the Response headers it would be None
                        // and in the given approach we always have to check for it to be Some
                        // UPDATE: Not really, see todo.txt

                        println!("Redirecting from: {} | {}", domain.from, path);
                        println!("Redirecting to: {} | {}", location, path);
                        location.set_path(path);

                        // NOTE: This as it happens can be relative, so we could try to make it relative someday
                        headers.add("Location".into(), location.to_string().into());

                        headers.add(Cow::from("Content-Length"), Cow::from("0"));

                        let mut response: HttpResponse<'_> = HttpResponse::new(headers, None);

                        response.write(config, stream).await?;

                        return Ok(true);
                    }
                }
            }
            // }
            // To redirect based on paths, not the domain, you need to match appropriate header,
            // than we will parse to url::Url and try to match the path to the one in the config file
            // _ => (),
        }
        // }

        Ok(false)
    }
}
