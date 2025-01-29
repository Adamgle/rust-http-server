use core::panic;
use std::borrow::Cow;
use std::error::Error;
use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;
use std::{fs, thread};

use crate::config::Config;

use crate::http::{
    HttpHeaders, HttpProtocol, HttpRequestError, HttpRequestMethod, HttpRequestRequestLine,
    HttpResponseStartLine,
};

use crate::http_response::HttpResponse;

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
    pub fn new(config: &mut Config, stream: &mut TcpStream) -> Result<Self, Box<dyn Error>> {
        // Parse the TCP stream
        let (parsed_headers, body) = Self::parse_request(config, stream)?;

        Ok(Self {
            // headers,
            parsed_headers,
            body,
        })
    }

    // Parses headers from the String, returns HttpHeaders and optional body that comes with request
    // We know that `headers` is non empty stream read from TCPStream, UTF-8 encoded
    fn parse_request(
        config: &mut Config,
        stream: &mut TcpStream,
    ) -> Result<(HttpHeaders<'a>, Option<Vec<u8>>), Box<dyn Error>> {
        // Iterating over lines we will parse the headers in "real-time",
        // -> First we will look up the method of the request in request_line to tell should we expect the Content-Length
        //      of the resource that should get transferred, those include POST, PUT and UPDATE, rest we will consider without this
        //      type of header. Rest of the method do not pose a risk for missing bytes read, because they are not read
        //      they are written, so we will worry about that while writing to the stream.
        // -> Second we will just parse the headers by the delimiter: ": ", composing key-value pairs
        // -> Third requests methods POST, PUT, UPDATE "COULD" contain a payload coming with the request, I have investigated that the
        //      payload come as a separate TcpStream that gets assembled during the transmission and I suspect that is the reason
        //      of incomplete messages send to the server, because the server does not know the expected payload size
        //      but if I think about it during GET request the server does not know the size of the payload either, maybe the problem only
        //      consists of chunked streaming. Besides that, we will look for an empty line as the CRLF gets removed by the BufReader::lines()
        //      and we will treat the rest of the stream as the body of the request, if present.
        // NOTE: Generally this approach does not seem to target out issue with incomplete POST, PUT, UPDATE messages

        // UPDATE: We are changing our approach of reading that data as lines to reading it as chunks
        // of 32 bytes, looking for Content-Length header in POST, PUT, UPDATE requests

        // How it works:
        // We are writing to chunks of 32 bytes in size, looking for common delimiters
        // We are looking for CRLF's and ": " as they delimit the headers and key-value pairs of headers accordingly
        // We need to make sure that after parsing of headers present in chunk, everything that is left unparsed
        // (because there could be incomplete headers written to the chunk) will be saved in the next chunk waiting for
        // completion by the next chunk
        // There could be a big issue with that approach. What if the read chunk does not contain any valid header fields?
        // if we would overwrite the chunk, the the whole data would be lost. We would have to buffer that data
        // until a valid header shows up that completes the previous chunk. We could allocate an internal buffer
        // for that or just write to the existing buffer, somehow get the location of the written chunk
        // read it and consider the chunk as a whole, whatever we wrote to the buffer being the previous chunk
        // and the current chunk written from the stream. Actually the stored buffer is strictly unnecessary
        // because we really do not care about the full headers, we just want to parse that data to the
        // desired format and what we are doing is parsing the stream as we read it

        // There are 2 ongoing issue with the headers parsing
        // 1. Sometimes the delimiter will be split between two chunks, we need to account for that
        // 2. There is a security vulnerability of passing additional unexpected delimiters like CRLF's and ": " I guess would also
        //  pose a risk

        // Issue 2 -> Header injection
        // -> Content-word: kasdjaksdjaskd
        // Content-word:
        // 'Content-word: '\r\n<value = Host: localhost:3000\r\n
        // 'Host: localhost:3000'\r\n

        // Issue 1
        // Content-Type:
        //  laskdjaksldj\r\n

        // Error out after 5 seconds if request is not fully read
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;

        const CHUNK_SIZE: usize = 1024;
        const DELIMITER_SIZE: usize = 2;
        const LFCRLF_SIZE: usize = 3;

        let mut chunk = [0u8; CHUNK_SIZE];

        let (mut curr_key, mut curr_value): (Option<Vec<u8>>, Option<Vec<u8>>) = (None, None);

        // This is actually not optional but we would have to make a separate loop for parsing the request_line
        let mut headers: Option<HttpHeaders> = None;
        let mut start_line = Vec::<u8>::new();

        let mut body: Option<Vec<u8>> = None;
        let mut lfcrlf_shift = 0usize;

        'outer: loop {
            let bytes_read = stream.read(&mut chunk);

            // `pointer` gives a position to the unparsed portion of the chunk
            let mut pointer = 0usize;

            match bytes_read {
                Ok(bytes_read) => {
                    if let Some(headers) = headers.as_ref() {
                        // Check for the Content-Length header, it MUST be present when body is present in cases of POST, PUT, UPDATE methods
                        // although the payload could be empty, but the header should be present.

                        if let Some(content_length) = headers.get("Content-Length") {
                            if let Ok(content_length) = content_length.parse::<usize>() {
                                // No body, acceptable
                                if content_length == 0 {
                                    break;
                                }
                                // Should be present at that point, although we check for it to be some
                                else if let Some(body) = &mut body {
                                    // Filling body, LFCRLF already removed
                                    if lfcrlf_shift == LFCRLF_SIZE {
                                        body.extend_from_slice(&chunk[..bytes_read]);
                                    } else {
                                        let remaining_lfcrlf_shift = LFCRLF_SIZE - lfcrlf_shift;
                                        body.extend_from_slice(
                                            &chunk[remaining_lfcrlf_shift..bytes_read],
                                        );
                                    }

                                    let size = body.len();

                                    match size.cmp(&content_length) {
                                        // Fully read, request parsed!
                                        std::cmp::Ordering::Equal => break,
                                        // Anomaly happened
                                        std::cmp::Ordering::Greater => {
                                            eprintln!("Payload size was greater than expected: Body size greater than content_length: Body size: {} > {} <| Content-Length", body.len(), content_length);
                                            return Err(
                                                format!("Payload size was greater than expected: Body size greater than content_length: Body size: {} > {} <| Content-Length", body.len(), content_length),
                                            )?;
                                        }
                                        // Still reading
                                        std::cmp::Ordering::Less => continue,
                                    }
                                }
                            }
                        }
                    }

                    for (pos, window) in chunk.windows(2).enumerate() {
                        // println!("Window: {:?} pos: {pos} pointer: {pointer} curr_key {:?} curr_value {:?} headers is some {:#?}",
                        //     String::from_utf8_lossy(window),
                        //     String::from_utf8_lossy(&curr_key.clone().unwrap_or(Vec::new())),
                        //     String::from_utf8_lossy(&curr_value.clone().unwrap_or(Vec::new())),
                        //     "---");

                        if headers.is_none() {
                            if window == b"\r\n" {
                                start_line.extend_from_slice(&chunk[pointer..pos]);

                                let request_line = String::from_utf8_lossy(&start_line);

                                let request_line =
                                    HttpRequestRequestLine::new(config, &request_line)?;

                                headers = Some(Self::new_headers(request_line));

                                // Reset the start_line, clear the memory, although that would be dropped when gone out of scope
                                start_line.clear();

                                pointer = pos + DELIMITER_SIZE;
                            }
                        } else {
                            // NOTE: This is stupid
                            // Check for message body or end of request
                            // Two consecutive CRLF sequences separate headers from body
                            // First window shows \r\n, second shows \n\r
                            // If no body present, this marks end of request
                            // If body present for POST/PUT/UPDATE, remaining data is body content

                            // Check for partial delimiters, synchronize delimiters across chunks
                            // Check if the prev_key does not contain partial delimiter ":" without preceding space: " "
                            // That could happen if delimiter is splitted between two chunks, we need to synchronize that

                            if let Some(prev_key) = &mut curr_key {
                                // NOTE: This can pose a vulnerability of incorrect headers parsing
                                // if the user send message like: Chunk_1 <key>:
                                //                                Chunk_2 <val ue>
                                //                                curr_key would be: key, "val" would be ignored space would also be ignored, "ue" would be written to curr_value
                                // ":", " "
                                if prev_key.len() != 0
                                    && prev_key[prev_key.len() - 1] == b':'
                                    && window[0] == b' '
                                {
                                    // Remove incomplete delimiter, rest of the key is valid, fully read key
                                    prev_key.pop();

                                    // Remainder of the window should be written to the value
                                    // 1..2 rest of the window now written to the value
                                    curr_value = Some(chunk[pos + 1..pos + 2].to_vec());

                                    pointer = pos + DELIMITER_SIZE;
                                }
                            }

                            if let Some(prev_value) = &mut curr_value {
                                if prev_value.len() != 0
                                    && prev_value[prev_value.len() - 1] == b'\r'
                                    && window[0] == b'\n'
                                {
                                    prev_value.pop();

                                    // This ends the header parsing, we have key and value presumably defined
                                    if let Some(headers) = headers.as_mut() {
                                        headers.add_header_binary(&mut curr_key, &mut curr_value);
                                    } else {
                                        panic!("You fucked up headers! They are None even thought they are supposed to be already defined at this point")
                                    }

                                    // Take rest of the window for further parsing, this would be fragment of key
                                    curr_key = Some(chunk[pos + 1..pos + 2].to_vec());

                                    pointer = pos + DELIMITER_SIZE
                                }
                            }

                            if window == b"\n\r" {
                                let method = headers
                                    .as_ref()
                                    .unwrap()
                                    .get_request_line()
                                    .unwrap()
                                    .get_method();

                                match method {
                                    // Body COULD BE present
                                    HttpRequestMethod::POST
                                    | HttpRequestMethod::PUT
                                    | HttpRequestMethod::UPDATE => {
                                        // This branch will begin to read body from the request, if payload is big enough it
                                        // could not be present at this moment, ideally we would make this parser async, but
                                        // we will try to wait for the data to appear in the stream
                                        // there is also a possibility of empty body so Content-Length header should be checked
                                        // to match the desired size of the body

                                        // NOTE: This is shit, not sure even if this works in all cases
                                        lfcrlf_shift = if pos + LFCRLF_SIZE < CHUNK_SIZE - 1 {
                                            LFCRLF_SIZE
                                        } else {
                                            // LFCRLF_SIZE + 1 for maximum value to be LFCRLF_SIZE, then possible values could be 0, 1, 2, 3
                                            (pos + LFCRLF_SIZE) % (LFCRLF_SIZE + 1)
                                        };

                                        // Check if the body is expected to arrive, if not arrived yet
                                        if let Some(headers) = headers.as_ref() {
                                            if let Some(Ok(content_length)) = headers
                                                .get("Content-Length")
                                                .map(|s| s.as_ref().parse::<usize>())
                                            {
                                                let read_to = if pos + lfcrlf_shift + content_length
                                                    <= CHUNK_SIZE
                                                {
                                                    pos + lfcrlf_shift + content_length
                                                } else {
                                                    CHUNK_SIZE
                                                };

                                                let body_chunk =
                                                    &chunk[pos + lfcrlf_shift..read_to];

                                                if content_length != 0 {
                                                    let size = body_chunk.len();

                                                    body = Some(body_chunk[..size].to_vec());

                                                    // Fully read, break the loop, request parsed!
                                                    if content_length == size {
                                                        break 'outer;
                                                    }
                                                } else {
                                                    // Content-Length not present, should not happen
                                                    eprintln!("Content-Length not present in the headers while methods being: POST, PUT, UPDATE");
                                                    return Err(
                                                        format!("Content-Length not present in the headers while methods being: POST, PUT, UPDATE"),
                                                    )?;
                                                }
                                            }
                                        }
                                        break;
                                    }
                                    // End of request parsing
                                    _ => break 'outer,
                                };
                            } else if window == b": " {
                                let key = &chunk[pointer..pos];

                                // In this case bytes left in chunk was written in curr_key
                                if let Some(prev_key) = curr_key.as_mut() {
                                    prev_key.extend_from_slice(key);
                                } else {
                                    curr_key = Some(key.to_vec());
                                }

                                pointer = pos + DELIMITER_SIZE;
                            } else if window == b"\r\n" {
                                // If CRLF is encountered, then it is assumed that we have key-value pair ready to be parsed
                                // NOTE: There is a problem because my headers API does not support [u8] slices as a key-value pairs
                                // Quick workaround or maybe it can even stay this way would be to convert the key-value pair to a String

                                // NOTE: Check for two continuous CRLF's, that would mean the end of request
                                // or the body of the request

                                let value = &chunk[pointer..pos];

                                // In this case bytes left in chunk was written in curr_value
                                if let Some(prev_value) = curr_value.as_mut() {
                                    prev_value.extend_from_slice(value);
                                } else {
                                    curr_value = Some(value.to_vec());
                                }

                                if let Some(headers) = headers.as_mut() {
                                    headers.add_header_binary(&mut curr_key, &mut curr_value);
                                } else {
                                    panic!("You f'ed up headers! They are None even thought they are supposed to be already defined at this point")
                                }

                                // Reset value
                                // (curr_key, curr_value) = (None, None);

                                pointer = pos + DELIMITER_SIZE;
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data yet, sleep a bit and retry
                    println!("Waiting for data...");
                    thread::sleep(Duration::from_millis(1000));
                }
                Err(e) => {
                    eprintln!("Error reading from the stream: {}", e);
                    return Err(e)?;
                } // Handle real errors
            }

            // If we did not encounter CRLF in the last chunk while parsing the start_line
            // we will write entire chunk of data to the start_line

            if headers.is_none() {
                start_line.extend_from_slice(&chunk);
            }
            //
            // After the loop, if the curr_key is Some we write everything in the buffer to the curr_value
            // If the curr_value is Some we write everything in the buffer to the curr_key
            // that observation is derived from the fact that if last significant byte was a colon then everything before it
            // was written to the key, the rest of the content, if no CRLF occurred, should be considered a value,
            // which could not be complete so we need to keep in mind that the next chunk should write to the variable
            // that was buffered there
            else if curr_key.is_some() {
                curr_value
                    .as_mut()
                    .map(|v| {
                        v.extend_from_slice(&chunk[pointer..]);
                        v
                    })
                    .or(Some(&mut chunk[pointer..].to_vec()));
            } else if curr_value.is_none() {
                curr_key
                    .as_mut()
                    .map(|v| {
                        v.extend_from_slice(&chunk[pointer..]);
                        v
                    })
                    .or(Some(&mut chunk[pointer..].to_vec()));
            }
        }

        stream.shutdown(std::net::Shutdown::Read)?;
        Ok((headers.unwrap(), body))
    }

    pub fn get_body(&self) -> Option<&Vec<u8>> {
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
    pub fn redirect_request(
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

                                    response.write(config, stream)?;

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
