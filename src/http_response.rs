use crate::config::Config;
use crate::http::{HttpHeaders, HttpProtocol, HttpRequestError, HttpResponseStartLine};
use std::error::Error;
use std::io::Write;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::prelude::*;

#[derive(Debug)]
pub struct HttpResponse<'a> {
    body: Option<String>, // This could be [u8] bytes Or just `Bytes` struct, because that is at the lower level and actually every resource in TCP is stream as chunks of u8 bytes.
    headers: HttpHeaders<'a>,
    // serialized: Option<Vec<u8>>,
}

impl<'a> HttpResponse<'a> {
    pub fn new(
        response_headers: HttpHeaders<'a>,
        body: Option<String>,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            body,
            headers: response_headers,
            // Maybe we would implement some sort of a middleware, and would want for it to affect the response then we could store it, but
            // actually either way it would be better to just mutate the parsed version instead of serialized and just sent the requests
            // after the middleware done it's job.
            // serialized: None,
        })
    }

    /// Initializes HttpHeaders with start line, providing default value for headers field with `HashMap::<&str, Cow<str>>::new()`
    /// Start line is initialized with `HTTP/1.1 200 OK` status code and status text,
    /// custom start line as an argument to the function.
    pub fn new_headers(start_line: Option<HttpResponseStartLine<'a>>) -> HttpHeaders<'a> {
        HttpHeaders::new(
            match start_line {
                Some(start_line) => Some(start_line),
                None => HttpResponseStartLine::new(HttpProtocol::HTTP1_1, 200, "Ok").into(),
            },
            None,
        )
    }

    /// Parses headers field  from HashMap<String, String> and body to Vec<u8> bytes vector and saves it in parsed_headers field
    /// This could return an error when data is semantically incorrect then parsing would fail
    fn parse_http_message(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        // QUESTION: Can we allocate statically sized buffer for that
        // ANSWER: No, because we cannot predict the size of the response at compile time
        // thought we could look onto Vec::with_capacity method to optimize the allocation

        // TODO: Allocate static buffer size for response bytes
        // NOTE: This cannot be allocate as it would have to be allocated in the runtime
        // as the data that comes with response is dynamically sized and we
        // cannot predict the size of the response at compile time. Thought we could
        // look onto Vec::with_capacity method to optimize the allocation
        // so to avoid resizing data, but that would be just premature optimization

        let mut buffer = Vec::<u8>::new();

        // start-line serialization

        buffer.extend(self.headers.get_start_line().map_or_else(
            || {
                Err(HttpRequestError {
                    message: "Start line is missing".to_string().into(),
                    ..Default::default()
                })
            },
            |start_line| Ok(start_line.to_string().as_bytes().to_vec()),
        )?);

        // Write line with key-value pair structuring a header

        for (key, value) in self.headers.get_headers() {
            write!(buffer, "{}: {}\r\n", key, value)?;
        }

        if let Some(body) = &self.body {
            write!(buffer, "\r\n{}", body)?;
        }

        // NOTE: Generally speaking saving serialized response in struct is useless after we sent the response

        Ok(buffer)
    }

    fn show_request_outcome(&self) {
        println!("Response: {}", self.headers.get_start_line().unwrap())
    }

    pub async fn write(
        &mut self,
        config: &MutexGuard<'_, Config>,
        stream: &mut TcpStream,
    ) -> Result<(), Box<dyn Error>> {
        // let mut logger = Logger::new()?;
        // config
        //     .logger
        //     .log_tcp_stream(format!("--- Response ---\r\n{:?}\r\n", self.headers))?;

        self.show_request_outcome();
        let data = self.parse_http_message().unwrap();

        // println!("Size of response payload: {}", data.len());

        stream.writable().await?;

        // Refactor to Anyhow::Result
        stream
            .write_all(&data)
            .await
            .inspect_err(|_| println!("Could not write to the stream"))?;

        stream
            .flush()
            .await
            .inspect_err(|_| println!("Could not flush the stream after writing to it"))?;

        stream.shutdown().await?;
        Ok(())
    }
}
