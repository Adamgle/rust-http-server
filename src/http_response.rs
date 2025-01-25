use crate::http::{HttpHeaders, HttpProtocol, HttpResponseStartLine};
use crate::logger::Logger;
use std::error::Error;
use std::io::{self, Write};
use std::net::{self, TcpStream};

#[derive(Debug)]
pub struct HttpResponse<'a> {
    body: Option<String>, // This could be [u8] bytes Or just `Bytes` struct, because that is at the lower level and actually every resource in TCP is stream as chunks of u8 bytes.
    headers: HttpHeaders<'a>,
    serialized: Option<Vec<u8>>,
}

impl<'a> HttpResponse<'a> {
    /// Initializes HttpResponse and adds appropriate headers based on request_headers
    ///
    /// If request_headers are None, it means responding with some kind of critical error, regardless of the request

    // NOTE: I find it very stupid that writing headers is somehow automated
    // so we will opt out of that idea.
    pub fn new(
        response_headers: HttpHeaders<'a>,
        body: Option<String>,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            body,
            headers: response_headers,
            serialized: None,
        })
    }

    /// Initializes HttpHeaders with start line, providing default value for headers field with `HashMap::<&str, Cow<str>>::new()`
    /// Start line is initialized with `HTTP/1.1 200 OK` status code and status text,
    /// any errors and changes to start line COULD be done after initialization on the mutable reference to the headers
    /// or by providing custom start line as an argument to the function.
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
    fn parse_http_message(&mut self) -> Option<&Vec<u8>> {
        // CONCLUSION: We could allocate static size buffer but this is just unnecessary and error prone,
        // using reference is impossible because we are parsing the data in self.headers and self.start_line]
        // making it own the data underneath effectively coping the data from headers with additional overhead,
        // so we need to allocate the buffer that owns every chunk of parsed data.

        let mut buffer = Vec::<u8>::new();

        // start-line formatting
        buffer.extend(
            self.headers
                .get_start_line()
                .unwrap()
                .to_string()
                .as_bytes(),
        );

        // Write line with key-value pair structuring a header
        // headers formatting
        buffer.extend(self.headers.get_headers().iter().fold(
            Vec::<u8>::new(),
            |mut acc, (key, value)| {
                acc.extend(format!("{key}: {value}\r\n").as_bytes());
                acc
            },
        ));

        // body formatting
        if let Some(body) = &self.body {
            // injecting additional; CRLF before body
            buffer.extend("\r\n".as_bytes());

            buffer.extend(body.as_bytes());
        }

        // NOTE: Generally speaking saving serialized response in struct is useless after we sent the response
        self.serialized = Some(buffer);

        self.serialized.as_ref()
    }

    pub fn write(&mut self, stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
        let mut logger = Logger::new()?;
        logger.log_tcp_stream(format!("--- Response ---\r\n{:#?}\r\n", self.headers))?;

        let data = self.parse_http_message().unwrap();

        println!("Size of response payload: {}", data.len());

        // This requires to copy the stream, not sure if that is acceptable
        let mut writer = io::BufWriter::with_capacity(1024 * 1024, stream.try_clone()?);

        let bytes_written = writer.write(data)?;

        // Essential to call flush, as stated in the documentation
        writer.flush()?;

        if bytes_written < data.len() {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("Sent {}/{} bytes", bytes_written, data.len()),
            ))?;
        }

        stream.flush()?;
        stream.shutdown(net::Shutdown::Write)?;
        Ok(())
    }
}
