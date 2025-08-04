pub mod config;
pub mod http;
pub mod prelude;
pub mod router;

pub use http::http_request;
pub use http::http_response;

use std::error::Error;

use crate::prelude::*;

pub mod tcp_handlers {
    use super::http_request::HttpRequest;
    use crate::config::Config::{self};
    use crate::http::{HttpHeaders, HttpResponseHeaders, HttpResponseStartLine};
    use crate::http_response::HttpResponse;
    use crate::router::cache::RouterCache;
    use crate::router::{RouteContext, RouteHandlerResult, RouteTableKey};
    use crate::*;
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
                        // let writer = Arc::clone(&writer);

                        if let Err(err) = self::handle_client(
                            &mut reader,
                            Arc::clone(&writer),
                            Arc::clone(&config),
                        )
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

    /// Handles incoming request from the client.
    async fn handle_client(
        reader: &mut OwnedReadHalf,
        writer: Arc<Mutex<OwnedWriteHalf>>,
        config: Arc<Mutex<Config>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let config = Arc::clone(&config);
        let config = config.lock().await;

        let writer = Arc::clone(&writer);
        let mut writer = writer.lock().await;

        let request = HttpRequest::new(&config, reader, &mut writer).await?;

        let (path, method) = (request.get_request_target_path()?, request.get_method());

        info!("State of cache: {:#?}", RouterCache);

        // NOTE: We could just create those headers while doing route and then return the ownership.
        // it would be the same actually, we would still return it from the route handler, but maybe more idiomatic.
        let headers: HttpResponseHeaders<'_> =
            HttpResponseHeaders::new(HttpResponseStartLine::default());

        let router = config.get_router();

        let route_key = RouteTableKey {
            path: PathBuf::from(path),
            method: Some(method.clone()),
        };

        // println!("Incoming: {:?}", route_key);
        info!("Incoming request: #{:?}", route_key);

        // To resolve the double mutable reference to headers we will move the ownership of headers
        // that is cheap operation.

        let ctx = RouteContext::new(
            request,
            headers,
            &route_key,
            config.app.get_database(),
            // We are cloning the database config
            config.get_database_config().cloned(),
        );

        let ctx = ctx.into_owned();

        // That is impossible due to lifetime issues.
        // let result = match router.route(ctx).await? {
        //     AnyRouteResult::RouteResult(result) => result,
        //     AnyRouteResult::OwnedRouteResult(result) => result.to_borrowed(),
        // };

        // We have to match it explicitly

        // match RouterCache::get(&route_key) {
        //     Some(result) => match result {
        //         router::cache::RouterCacheResult::AppControllerResult(app_result) => todo!(),
        //         router::cache::RouterCacheResult::RouteResult(result) => match result {
        //             router::cache::OwnedRouteResult::Route(owned_route_handler_result) => todo!(),
        //             router::cache::OwnedRouteResult::Middleware(
        //                 owned_middleware_handler_result,
        //             ) => {
        //                 // If the middleware segment exists, we run the middleware for that segment.
        //                 // We do not want to propagate the error here, as we want to return the context back to the route handler.
        //                 let context = owned_middleware_handler_result.ctx.to_borrowed();
        //                 router.route(context).await?;
        //             }
        //         },
        //     },
        //     None => todo!(),
        // };

        let RouteHandlerResult { mut headers, body } = router.route(ctx.to_borrowed()).await?;

        // let result = match &mut result {
        //     AnyRouteResult::Borrowed(r) => r,
        //     AnyRouteResult::Owned(r) => &mut r.to_borrowed(),
        // };

        headers.add(Cow::from("Connection"), Cow::from("keep-alive"));

        let mut response: HttpResponse<'_> = HttpResponse::new(&headers, Some(Cow::from(body)));

        response.write(&config, &mut writer).await?;

        Ok(())
    }
}
