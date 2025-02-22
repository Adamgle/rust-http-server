use crate::config::Config;

use std::borrow::Cow;
use std::char::UNICODE_VERSION;
use std::error::Error;
use std::fs;
use std::io::Bytes;
use std::ops::Index;
use std::path::{Path, PathBuf};
use std::str::Utf8Error;
use std::task::Context;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
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
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Parse the TCP stream
        let (mut parsed_headers, body) = match Self::parse_request(&config, stream).await {
            Ok(it) => it,
            Err(err) => {
                eprintln!("Could not parse request: {}", err);

                // Shutdown the stream for writing if any error occurs
                stream.shutdown().await?;

                return Err(err);
            }
        };

        // println!("Headers keys: {:#?}", parsed_headers.get_headers().keys());

        // NOTE: I thing the discrepancy between the domain used here should be resolved thought should be investigated first
        // requested_target => http://localhost:5000/ It uses config to build the url as the default from the domain and port
        //  -> thought if the request is made from different domain, first off all it is not possible,
        //  -> thought could be possible if the request gets redirected.
        //  -> Host: 127.0.0.1:5000 => request_target => localhost:5000
        // NOTE: Something like this should be done

        // To avoid ambiguity we could change the default domain to whatever comes with host header
        let host = parsed_headers.get("Host").map(|host| host.to_string());

        if let Some(request_line) = parsed_headers.get_request_target_mut() {
            if let Some(host) = host {
                // This will not show a distinction between 127.0.0.1 and localhost as this resolves 127.0.0.1 to localhost
                request_line
                    .set_host(Some(&host))
                    .expect("Could not set host");
            }
        }

        Ok(Self {
            parsed_headers,
            body,
        })
    }

    /// Parses http request from the TcpStream
    async fn parse_request(
        config: &MutexGuard<'_, Config>,
        stream: &mut TcpStream,
    ) -> Result<(HttpHeaders<'a>, Option<Vec<u8>>), Box<dyn Error + Send + Sync>> {
        // ONGOING FIXES

        // TODO: Verify the presence of the Host header, 400 if not present
        // Also make the headers validation as there is none at the moment, not only the Host header.

        // Could be None if TcpStream is not valid HTTP message.
        let mut headers: Option<HttpHeaders> = None;

        stream.readable().await.inspect_err(|e| {
            eprintln!("Stream is currently unreadable, but it will be!: {}", e);
        })?;

        let reader = BufReader::new(&mut *stream);
        let mut lines = reader.lines();

        while let Some(line) = lines.next_line().await.inspect_err(|e| {
            eprintln!("Error reading line from the stream: {}", e);
        })? {
            if line.is_empty() {
                break;
            } else {
                // First line is request line
                if headers.is_none() {
                    headers = Some(Self::new_headers(
                        HttpRequestRequestLine::new(&config, &line).await?,
                    ));
                } else {
                    // Error should not happen if the http message is semantically correct

                    headers
                        .as_mut()
                        .ok_or("Invalid request")
                        .map_err(|e| {
                            eprintln!(
                                "Headers are not initialized while parsing header from line."
                            );
                            e
                        })?
                        .add_header_line(line);
                }
            }
        }

        // TESTING
        // TESTING

        // if let Some(injected_header) = headers.as_ref().and_then(|h| h.get("Injected-Header")) {
        //     println!(
        //         "\x1b[93mInjected Header size: {:#?}\x1b[0m",
        //         injected_header.len()
        //     );

        //     drop(lines);

        //     let keys = headers.as_ref().unwrap().get_headers().keys().len();
        //     stream
        //         .write(format!("{};{}", injected_header.len(), keys).as_bytes())
        //         .await?;

        //     stream.shutdown().await?;

        //     return Ok((HttpHeaders::new(None, None), None));
        // } else {
        //     println!("Injected Header not found");
        // }

        // TESTING
        // TESTING

        // Read the rest of the stream, if any
        // Body of the request will only be present if the request method is POST, PUT, UPDATE/PATCH
        // and when the Content-Length header is present in the headers

        if let Some(headers) = headers {
            let mut body_buffer: Option<Vec<u8>> = None;

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
                            println!("Called");
                            break;
                        }

                        body_buffer.as_mut().unwrap().extend_from_slice(chunk);

                        let bytes_read = chunk.len();
                        reader.consume(bytes_read);
                        transferred += bytes_read;
                        // println!("Transferred: {}/{}", transferred, content_length);
                    }
                }
            }

            // stream.shutdown()
            Ok((headers, body_buffer))
        } else {
            eprintln!("Headers are not initialized");
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
    /// Checks for existence of the path, return error if the path does not exists
    ///
    /// `NOTE`: We will not support matching paths without extensions for now
    /// last segment without extension will be treated as a directory and we will try to find index.html in that directory
    ///
    /// NOTE: Paths `/pages/index.html` and `/index.html` and "/" are valid paths that point to `/pages` directory on `index.html` file.
    pub fn get_absolute_resource_path(
        &self,
        // config: &MutexGuard<'_, Config>,
    ) -> Result<PathBuf, HttpRequestError> {
        match self.get_request_target() {
            Ok(path) => {
                // 2. We will map specialized directories to the extension of the file requested, so if the file is requested with .html extension
                // we will look in the /public/pages directory, if the file is requested with .css extension we will look in the /public/styles directory
                // thought that solution cannot predict the requested path if it does not end with an extension that would resolve to appropriate directory
                // In that case, if the requested_path does not contain a file extension as the last segment, we would treat that as a directory,
                // thought we have to check if it is not a file without an extension, and then we would try to find index.html in that directory.

                // If file extension does not fall into the mapping, we would just traverse the directory, joining the path to the public directory
                // and try to match an existing path. If the path does point to a file or has no extension, there is not way in current approach to detect
                // it's type, we will throw an error in that case as we cannot know the type of the file and we cannot serve it. The same if the path points to a directory

                // DESIGN NOTE: We will support default files of the directories in the path, only as index.html as the default. Other specialized directories will not
                // try to resolve any paths when not given with full filename.

                // /asd, data.json, data
                // ../public, /asd/index.html => ../public/pages/asd/index.html
                // ../public, /asd/asd/asd/asd/ => CHECK =====../public/pages/asd/asd/asd/asd/index.html ===== => EXISTS
                // But what if there is no index.html in the path?
                // ../public/asd/data.json
                // ../public/pages/asd/data/pages/data.html

                let public = Config::get_server_public();

                let path: String = path.to_string();

                // NOTE: Error handling should be done here
                let path = Path::new(&path).strip_prefix("/").expect("Invalid path");

                // If that would be absolute and would join with the public directory path, it would create a new absolute path
                // effectively allowing to traverse the file system of the server

                // I do not know if that is stable enough, as windows has weird absolute path handling
                // Technically, you can if path.is_relative() {}

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

                // Whenever we use join we need to make sure the path is not absolute as that would construct a path from the root
                // allowing to traverse the file system

                // Routing to /pages, /styles, /client is undefined behavior, as those paths are not accessible by the client directly

                match path.extension() {
                    Some(ext) => {
                        // We need to check if the path is not of a pages.html or styles.css or client.js type
                        // as that would not prefix the path with the directory
                        // if we would do path.starts_with(dir)

                        let dir = ext
                            .to_str()
                            .map(|ext| match ext {
                                // pages styles, and client should not be String, enum for those should be declared
                                "html" => Some("pages"),
                                "css" => Some("styles"),
                                "js" => Some("client"),
                                // Actually if the extension does not fall into the mapping THEN you should iterate over public try to find the path
                                // NOTE: I do not think that is the way to do it, bad by design, not how file system works.
                                _ => None,
                            })
                            .flatten();

                        let path = match dir {
                            Some(dir) => {
                                // Handle cases where the path is already prefixed with the directory
                                // considering the filenames that are of the name of specialized directories
                                // to not avoid avoiding the prefixing with specialized directory

                                if (path.starts_with(dir)
                                    && path.file_stem().unwrap().to_str().unwrap() == dir)
                                    || path.starts_with(dir)
                                {
                                    // Do not prefix that
                                    public.join(path)
                                } else {
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
                        // If file extension does not fall into the mapping, we would just traverse the directory, joining the path to the public directory
                        // and try to match an existing path. If the path does point to a file or has no extension, there is not way in current approach to detect
                        // it's format, we will throw an error in that case as we cannot know the format of the file and we cannot serve it. The same if the path points to a directory

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
            self.parsed_headers
                .get_request_target()
                .map(|s: &url::Url| s.path())
                // TODO: Think about improving the error handling there
                .expect("Invalid request target, does not follow a scheme of a path.")
                .as_bytes(),
        )
        .decode_utf8()
    }

    /// Takes Response `HttpHeaders` and write `Content-Type` and `Content-Length` headers, returning the requested resource as a String
    /// Walks `/public` directory looking for path
    pub fn read_requested_resource(
        &'a self,
        response_headers: &mut HttpHeaders<'a>,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let resource_path: PathBuf = self.get_absolute_resource_path()?;

        let relative_path = resource_path
            .strip_prefix(Config::get_server_public())
            .expect("Server public directory is not a prefix of the requested resource")
            // clone there
            .to_owned();

        // target: /data/data.json
        // json would not try to resolve to pages and styles
        // target: /data/data.html
        // take the extension, parse to OsStr to str, match the extension, we do not care about it being directory or file without extension in this case
        // as it would resolve either way to error as the path does not exists, although we could sacrifice some computation time.
        // pages => []
        // asd => []
        // styles => []
        // boobies => []

        // Read the file
        let requested_resource = fs::read_to_string(resource_path)?;

        response_headers.add(
            Cow::from("Content-Length"),
            Cow::from(requested_resource.len().to_string()),
        );

        response_headers.add(
            Cow::from("Content-Type"),
            Cow::from(self.detect_mime_type(relative_path)),
        );

        return Ok(requested_resource);
    }

    /// I hate this, should be typed
    pub fn detect_mime_type(&self, request_target: PathBuf) -> &str {
        match self.parsed_headers.get("Content-Type") {
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
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
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

                                    println!("Redirect Path: {:#?}", path);
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
