use crate::config::Config;
use crate::http::{HttpHeaders, HttpRequestError, HttpResponseHeaders};
use std::error::Error;
use std::io::Write;

use crate::prelude::*;

use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;

#[derive(Debug)]
pub struct HttpResponse<'a> {
    body: Option<String>, // This could be [u8] bytes Or just `Bytes` struct, because that is at the lower level and actually every resource in TCP is stream as chunks of u8 bytes.
    /// Headers are created in the `handle_client` and we are referencing that data.
    headers: &'a HttpResponseHeaders<'a>,
    // serialized: Option<Vec<u8>>,
}

impl<'a, 'b> HttpResponse<'a> {
    pub fn new(headers: &'a HttpResponseHeaders<'a>, body: Option<String>) -> Self {
        Self {
            body,
            headers,
            // Maybe we would implement some sort of a middleware, and would want for it to affect the response then we could store it, but
            // actually either way it would be better to just mutate the parsed version instead of serialized and just sent the requests
            // after the middleware done it's job.
            // serialized: None,
        }
    }

    /// Parses headers field from HashMap<String, String> and body to Vec<u8>
    ///
    /// This could return an error when data is semantically incorrect
    fn parse_response(&mut self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        // QUESTION: Can we allocate statically sized buffer for that
        // ANSWER: No, because we cannot predict the size of the response at compile time
        // thought we could look onto Vec::with_capacity method to optimize the allocation

        // TODO: Allocate static buffer size for response bytes
        // NOTE: This cannot be allocated as it would have to be allocated in the runtime
        // as the data that comes with response is dynamically sized and we
        // cannot predict the size of the response at compile time. Though we could
        // look onto Vec::with_capacity method to optimize the allocation
        // so to avoid resizing data, but that would be just premature optimization

        // That is minimum that would be allocated, I am not sure about the performance improvement there
        // because that is not everything that would be allocated into that as the headers are not included in that.
        // NOTE: This sounds like reaching, I would not do that, not worth it with and error prone. But I think it is possible.
        // 1. To get the size of the headers we would either have to keep the size of it (serialized, so with CRLF and ": ") when
        // inserting the header in the HashMap, but that would require separate filed in struct, the same with the start line.
        // 2. We could also iterate over the headers, calculate it's parsed length and use it as a method on self.headers but
        // we would have to sacrifice performance of that iteration and would prefer to just not do that at all than do it this way.

        const BUFFER_CAPACITY_OFFSET: usize = 512;

        let content_length = self
            .headers
            .get("Content-Length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0)
            + BUFFER_CAPACITY_OFFSET;

        let mut response = Vec::<u8>::with_capacity(content_length);

        // start-line serialization
        response.extend(self.headers.get_start_line().to_string().as_bytes());

        // Write line with key-value pair structuring a header
        for (key, value) in self.headers.iter() {
            write!(response, "{}: {}\r\n", key, value)?;
        }

        if let Some(body) = &self.body {
            write!(response, "\r\n{}", body)?;
        }

        // NOTE: Generally speaking saving serialized response in struct is useless after we sent the response

        Ok(response)
    }

    /// `NOTE`: Internally check for writer being writable.
    pub async fn write(
        &mut self,
        config: &MutexGuard<'_, Config>,
        writer: &mut MutexGuard<'_, OwnedWriteHalf>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let data = match self.parse_response() {
            Ok(res) => res,
            Err(err) => {
                eprintln!("Error parsing response: {}", err);
                return Err(Box::new(HttpRequestError::default()));
            }
        };
        // short ----------
        // long     ----



        writer
            .writable()
            .await
            .inspect_err(|_| eprintln!("Stream is not writable"))?;

        writer
            .write_all(&data)
            .await
            .inspect_err(|_| println!("Could not write to the stream"))?;

        writer
            .flush()
            .await
            .inspect_err(|_| println!("Could not flush the stream after writing to it"))?;

        // Disregarded the error as it is not critical.

        writer.shutdown().await?;

        Ok(())
    }
}
