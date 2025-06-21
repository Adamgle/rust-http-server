pub mod config;
pub mod http;
pub mod logger;
pub mod middleware;
pub mod prelude;
pub mod routes;

pub use http::http_request;
pub use http::http_response;

use std::error::Error;

use crate::prelude::*;

pub mod tcp_handlers {
    use super::http_request::HttpRequest;
    use crate::config::Config::{self};
    use crate::http::{HttpHeaders, HttpResponseHeaders, HttpResponseStartLine};
    use crate::http_response::HttpResponse;
    use crate::routes::{RouteHandlerContext, RouteHandlerResult, RouteTableKey};
    use crate::*;
    use http::HttpRequestError;
    use std::borrow::Cow;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
    use tokio::net::TcpListener;
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

        println!(
            "TCP Connection Established at {:?}\nListening...",
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
                        eprintln!("Stream is not readable, skipping: {err:?}");
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
                            // This is error that occurs while handling the error.
                            if let Err(err) = HttpRequestError::send_error_response(
                                Arc::clone(&config),
                                Arc::clone(&writer),
                                err,
                            )
                            .await
                            {
                                eprintln!("Error sending error response: {}", err);
                            };

                            // The above code SHOULD release the lock so no deadlock, but keep in mind.
                            let mut writer = writer.lock().await;

                            // We need to ensure that the writer is shutdown, because if the
                            // error occurs while errors handling the http request, we could not
                            // shut it down.
                            if let Err(err) = writer.shutdown().await {
                                eprintln!("Error shutting down the stream: {}", err);
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
                        eprintln!("Error spawning task: {}", err);

                        let mut writer = task_error_writer.lock().await;

                        // Ensure the writer is shutdown, although it could already be shutdown
                        // Shut downs the writing portion of the stream if error occurs
                        if let Err(err) = writer.shutdown().await {
                            eprintln!("Error shutting down the stream: {}", err);
                        };
                    };

                    // Timeout for the request should be dependent on the method used or maybe even per path
                    // specifically for request with large payloads.
                    // if let Err(res) =
                    // tokio::time::timeout(tokio::time::Duration::from_secs(5), request_task)
                    // .await
                    // {
                    //     if let Err(err) = writer.shutdown().await {
                    //         eprintln!("Error shutting down the stream: {}", err);
                    //     }

                    // eprintln!("Request timed out: {}", res);
                    // }
                }
                Err(err) => eprintln!("Invalid TCP stream: {}", err),
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

        let mut headers = HttpResponseHeaders::new(HttpResponseStartLine::default());

        let routes = config.get_routes();

        // If path is invalid and cannot be encoded, that should end the request
        let path = request.get_request_target_path()?;

        let route_key = RouteTableKey::new(path, Some(request.get_method().clone()));

        println!("Requesting: {:?}", route_key);

        headers.add(Cow::from("Connection"), Cow::from("keep-alive"));

        println!(
            "Size of type headers: {:?} | Size of value headers: {:?}",
            std::mem::size_of::<HttpResponseHeaders>(),
            std::mem::size_of_val(&headers)
        );

        // To resolve the double mutable reference to headers we will move the ownership of headers
        // that is cheap operation, and hopefully solve the issue.
        let ctx = RouteHandlerContext::new(&request, headers, &route_key, config.get_database());

        let RouteHandlerResult { mut headers, body } = routes.route(ctx).await?;

        // Early propagate before writing to headers.
        let body = Some(body?);

        headers.add(Cow::from("Connection"), Cow::from("keep-alive"));

        let mut response = HttpResponse::new(&headers, body);

        response.write(&config, &mut writer).await?;

        Ok(())

        // This will be executed for every request and try to match paths that should be redirected
        // although the only redirection that we are doing is from http://127.0.0.1:<port> to http://localhost:<port>
        // paths are defined in the config file under 'domain' field, for domains and path redirect in the "paths" field

        // If we still want to declare that database there, we should do that whenever we are requesting it,
        // not in every request. That could be in pattern matching the path, but there is a potential that we could
        // match something more weakly and then some request would go to the wrong branch, so we know that when requesting
        // database the "database" keyword is in the first place of the path and we should stick to that, and there should be no extension
        // present in this segment so to not mistake it with a file like database.html, but the whole function should be refactored so just
        // to note that. Also the call to database is not expensive, but we it would be wise to do so as for some requests it is just useless.

        // let database = config.get_database()?;

        // If we would rely on HTTP methods to differentiate between requests to perform different logic,
        // we would limit ourselves to only one handler per method per path. We could of course
        // abstract that away, and just make custom endpoints for each handler we want to have.
        // But maybe since that is soo small project to test functionality of the server, we will rely on methods

        // let base_error = Err(HttpRequestError {
        //         status_code: 404,
        //         status_text: String::from("Not Found"),
        //         message: String::from("Path does not exist on the server or the method used is unsupported for that path").into(),
        //         content_type: "application/json".to_string().into(),
        //         internals: Some(Box::<dyn std::error::Error + Send + Sync>::from(
        //         format!("Path does not exist on the server or the method used is unsupported for that path: {:?}", path))),
        //     });

        // Refactored: match first on path, then on method
        // NOTE: For that to be more maintainable, each match on method could be a separate function.

        // We could think of refactoring that to the routes table as
        // HashMap<Path, HashMap<HttpRequestMethod, fn(&mut HttpRequest, &mut HttpResponseHeaders) -> Result<Option<String>, Box<dyn Error + Send + Sync>>>>,
        // That would have to be statically defined we would then make a static file out of it I guess for faster retrieval. We would also
        // include the files that in the SpecialDirectories caching the computation for walking in the file system to get the paths.
        // We still have those abstracted paths and those have to be hard-coded somewhere in the code. I guess we would have a HashMap
        // with the path as key and the closure that carries over also some data about the request.

        // let body: Option<String> = match &path {
        //     p if SpecialDirectories::collect()?.contains(p) => {
        //         // If the path is one of the special directories, we will just read the resource from the file system
        //         // Any paths under special directories can be requested by the client without API-key using GET requests
        //         match method {
        //             HttpRequestMethod::GET => Some(request.read_requested_resource(&mut headers)?),
        //             _ => return base_error?,
        //         }
        //     }
        //     // The trailing slash at the end is important, as that ensures there is no extension attached to the "database", meaning that is a file,
        //     // here we match the directory.
        //     // TODO: If there will be authentication done we should check if the user is authenticated to proceed to database
        //     // but not every request to the database should require authentication.
        //     p if p.starts_with("database/") => match config.config_file.database.as_ref() {
        //         Some(_) => match path {
        //             p if p == Path::new("database/tasks.json") => {
        //                 match method {
        //                     HttpRequestMethod::GET => {
        //                         Some(request.read_requested_resource(&mut headers)?)
        //                     }
        //                     HttpRequestMethod::POST => {
        //                         if let Some(task) = request.get_body() {
        //                             let mut database = database.lock().await;
        //                             database.insert(DatabaseType::Tasks, task).await?;
        //                             String::from("Ok").into()
        //                         } else {
        //                             Err("Task not provided in the request body")?
        //                         }
        //                     }
        //                     HttpRequestMethod::DELETE => {
        //                         if let Some(id) = request.get_body() {
        //                             let mut database = database.lock().await;
        //                             database.delete(DatabaseType::Tasks, id).await?;
        //                             // database.delete(DatabaseType::Tasks);

        //                             String::from("Ok").into()
        //                         } else {
        //                             Err("Id not provided in the request body")?
        //                         }
        //                     }

        //                     _ => return base_error?,
        //                 }
        //             }
        //             p if p == Path::new("database/users.json") => match method {
        //                 HttpRequestMethod::GET => {
        //                     Some(request.read_requested_resource(&mut headers)?)
        //                 }
        //                 HttpRequestMethod::POST => {
        //                     if let Some(body) = request.get_body() {
        //                         let mut database = database.lock().await;
        //                         database.insert(DatabaseType::Users, body).await?;

        //                         String::from("Ok").into()
        //                     } else {
        //                         Err("No body in the request")?
        //                     }
        //                 }
        //                 _ => return base_error?,
        //             },
        //             _ => return base_error?,
        //         },
        //         None => Err("Database not configured in the config file.")?,
        //     },
        //     _ => return base_error?,
        // };
    }
}
