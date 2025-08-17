pub mod config;
pub mod http;
pub mod prelude;
pub mod router;

pub use http::http_request;
pub use http::http_response;

use std::error::Error;

use crate::http_request::HttpRequest;
use crate::prelude::*;

// pub mod lib {
// use super::http_request::HttpRequest;
use crate::config::Config::{self};
use crate::http::{HttpHeaders, HttpResponseHeaders, HttpResponseStartLine};
use crate::router::RouteTableKey;
// use crate::*;

use http::HttpRequestError;
use log::{error, info};
use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;
use tokio::time::timeout;

pub async fn connect(
    config: MutexGuard<'_, Config>,
) -> Result<TcpListener, Box<dyn Error + Send + Sync>> {
    return TcpListener::bind(config.socket_address)
        .await
        .map_err(|e| e.into());
}

/// Starts TCP server with provided `Config`, continuously listens for incoming request and propagates them further.
pub async fn run_tcp_server(
    config: Arc<Mutex<Config>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // This extra lock will only affect first load time of the server and it is also negligible
    let listener = self::connect(config.lock().await).await?;

    info!(
        "TCP Connection Established at {:?}",
        listener.local_addr().unwrap()
    );

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                // That is the solution for the keep-alive packets that are sent to the server, kind of.

                // Wait for the stream to be readable before proceeding to parse it as http message
                // to not trigger the http error.
                // For packets like TCP-keep-alive stream will never be readable and is not a valid http message
                // so we abort early.

                // We don't want to propagate the error, because that would end out in the main loop.
                // and that is not a critical error.
                if let Err(err) =
                    timeout(tokio::time::Duration::from_secs(5), stream.readable()).await
                {
                    error!("Stream is not readable, skipping: {err:?}");
                    continue;
                };

                let (mut reader, writer) = stream.into_split();

                // I think writer is in Arc<Mutex<_>> because we want to also use it in case of the error
                // handling, but it gets moved into the task, since if we use the Arc for multiple owners
                // and Mutex as we need to write to writer and it should be mutable.
                let writer = Arc::new(Mutex::new(writer));

                let config = Arc::clone(&config);
                let task_error_writer = Arc::clone(&writer);

                let task = tokio::spawn(async move {
                    if let Err(err) =
                        self::handle_client(&mut reader, Arc::clone(&writer), Arc::clone(&config))
                            .await
                    {
                        error!("Error handling request: {}", err);

                        // This is error that occurs while handling the error.
                        if let Err(err) = HttpRequestError::send_error_response(
                            Arc::clone(&config),
                            Arc::clone(&writer),
                            err,
                        )
                        .await
                        {
                            error!("Error sending error response: {}", err);
                        };

                        // The above code SHOULD release the lock so no deadlock, but keep in mind.
                        let mut writer = writer.lock().await;

                        // We need to ensure that the writer is shutdown, because if the
                        // error occurs while errors handling the http request, we could not
                        // shut it down.
                        if let Err(err) = writer.shutdown().await {
                            error!("Error shutting down the stream: {}", err);
                        }
                    } else {
                        // Request termination, handled successfully
                    }
                });

                // Timeout on each task
                if let Err(err) =
                    tokio::time::timeout(tokio::time::Duration::from_secs(5), task).await
                {
                    // println!("Is task still running? {}", task.is_finished());
                    error!("Error spawning task: {}", err);

                    let mut writer = task_error_writer.lock().await;

                    // Ensure the writer is shutdown, although it could already be shutdown
                    // Shut downs the writing portion of the stream if error occurs
                    if let Err(err) = writer.shutdown().await {
                        error!("Error shutting down the stream: {}", err);
                    };
                };

                // Timeout for the request should be dependent on the method used or maybe even per path
                // specifically for request with large payloads.
                // if let Err(res) =
                // tokio::time::timeout(tokio::time::Duration::from_secs(5), request_task)
                // .await
                // {
                //     if let Err(err) = writer.shutdown().await {
                //         error!("Error shutting down the stream: {}", err);
                //     }

                // error!("Request timed out: {}", res);
                // }
            }
            Err(err) => error!("Invalid TCP stream: {}", err),
        }
    }
}

// Technically that is only related to HttpResponseHeaders, but I would delegate that as a library code.
pub fn set_default_headers(headers: &mut HttpResponseHeaders<'_>) {
    headers.add(Cow::from("Connection"), Cow::from("keep-alive"));
}

/// Handles incoming request from the client.
async fn handle_client(
    reader: &mut OwnedReadHalf,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    config: Arc<Mutex<Config>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let start = std::time::Instant::now();

    let config = Arc::clone(&config);
    let config = config.lock().await;

    let writer = Arc::clone(&writer);
    let mut writer = writer.lock().await;

    let request = HttpRequest::new(&config, reader, &mut writer).await?;

    let key = RouteTableKey {
        path: PathBuf::from(request.get_request_target_path()?),
        method: Some(request.get_method().clone()),
    };

    info!("Incoming request: #{:?}", key);
    // info!("State of cache: {}", RouterCache::debug());

    // NOTE: We could just create those headers while doing route and then return the ownership.
    // it would be the same actually, we would still return it from the route handler, but maybe more idiomatic.
    let mut headers = HttpResponseHeaders::new(HttpResponseStartLine::default());

    let router = config.get_router();

    // That is not ideal, but do not care.
    // It could be embedded in the Router::route, will keep it here. And also in real world application
    // functionality like that would likely serve no purpose.
    set_default_headers(&mut headers);

    let r = Ok(router.route(&config, &mut writer, request, headers).await?);

    info!("Route of {key:?} took: {} μs", start.elapsed().as_micros());

    return r;
}
// }
