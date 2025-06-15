pub mod config;
pub mod http;
pub mod logger;
pub mod prelude;

pub use http::http_request;
pub use http::http_response;

use std::error::Error;

use crate::prelude::*;

pub mod tcp_handlers {
    use super::http::HttpRequestMethod;
    use super::http_request::HttpRequest;
    use crate::config::database::DatabaseType;
    use crate::config::Config::{self};
    use crate::config::SpecialDirectories;
    use crate::http::{HttpHeaders, HttpResponseHeaders, HttpResponseStartLine};
    use crate::*;
    use http::HttpRequestError;
    use http_response::HttpResponse;
    use std::borrow::Cow;
    use std::path::Path;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    // QUESTION: Why is the server you are about to make is asynchronous, not multithreaded?
    // => FOLLOW UP QUESTION:
    //  -> Can certain tasks be handled in async manner and the other in threading manner. If any, which one should be handled in which way.
    // ANSWER: Handling multiple connection, which spawn it's separate thread is computationally heavy, may include a system call to spawn a thread,
    // otherwise in thread-pool.
    // Actually the dispute is to use async or threaded approach for handling requests
    // I will use async approach because sending a TCPStream is asynchronous task in time and the stream
    // can come at different intervals of time. Thread approach would be great if you would like to parallelize bunch of requests
    // that are independent of each other and this some sort of order of execution is not needed.

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

        // println!(
        //     "TCP Connection Established at {:?}\nListening...",
        //     listener.local_addr().unwrap()
        // );

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let (mut reader, writer) = stream.into_split();
                    let writer = Arc::new(Mutex::new(writer));

                    let config = Arc::clone(&config);
                    let task_error_writer = Arc::clone(&writer);

                    let task = tokio::spawn(async move {
                        let writer = Arc::clone(&writer);

                        if let Err(err) = self::handle_client(
                            &mut reader,
                            Arc::clone(&writer),
                            Arc::clone(&config),
                        )
                        .await
                        {
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

                            // Shutdown for writing
                            if let Err(err) = writer.shutdown().await {
                                eprintln!("Error shutting down the stream: {}", err);
                            }
                        } else {
                            // Request termination, handled successfully
                        }
                    });

                    if let Err(err) =
                        tokio::time::timeout(tokio::time::Duration::from_secs(5), task).await
                    {
                        eprintln!("Error spawning task: {}", err);

                        let mut writer = task_error_writer.lock().await;

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
        // writer: &mut OwnedWriteHalf,
        // writer: &mut MutexGuard<'_, OwnedWriteHalf>,
        config: Arc<Mutex<Config>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let config = Arc::clone(&config);
        let config = config.lock().await;

        let writer = Arc::clone(&writer);
        let mut writer = writer.lock().await;

        let request: HttpRequest<'_> = HttpRequest::new(&config, reader, &mut writer).await?;

        let mut headers: HttpResponseHeaders<'_> =
            HttpResponseHeaders::new(HttpResponseStartLine::default());

        let path = request.get_request_target_path()?;
        // If path is invalid and cannot be encoded, that should end the request

        let (method, path) = (request.get_method(), path);

        println!("REQUESTING: {} | {}", method, path.display());

        // This will be executed for every request and try to match paths that should be redirected
        // although the only redirection that we are doing is from http://127.0.0.1:<port> to http://localhost:<port>
        // paths are defined in the config file under 'domain' field, for domains and path redirect in the "paths" field

        // If we still want to declare that database there, we should do that whenever we are requesting it,
        // not in every request. That could be in pattern matching the path, but there is a potential that we could
        // match something more weakly and then some request would go to the wrong branch, so we know that when requesting
        // database the "database" keyword is in the first place of the path and we should stick to that, and there should be no extension
        // present in this segment so to not mistake it with a file like database.html, but the whole function should be refactored so just
        // to note that. Also the call to database is not expensive, but we it would be wise to do so as for some requests it is just useless.

        let database = config.get_database()?;

        // If we would rely on HTTP methods to differentiate between requests to perform different logic,
        // we would limit ourselves to only one handler per method per path. We could of course
        // abstract that away, and just make custom endpoints for each handler we want to have.
        // But maybe since that is soo small project to test functionality of the server, we will rely on methods

        let base_error = Err(HttpRequestError {
                status_code: 404,
                status_text: String::from("Not Found"),
                message: String::from("Path does not exist on the server or the method used is unsupported for that path").into(),
                content_type: "application/json".to_string().into(),
                internals: Some(Box::<dyn std::error::Error + Send + Sync>::from(
                format!("Path does not exist on the server or the method used is unsupported for that path: {:?}", path))),
            });

        // Refactored: match first on path, then on method
        // NOTE: For that to be more maintainable, each match on method could be a separate function.

        let body: Option<String> = match &path {
            // p if p == "/" => Some(request.read_requested_resource(&mut headers)?),
            p if SpecialDirectories::collect()?.contains(p) => {
                // If the path is one of the special directories, we will just read the resource from the file system
                // Any paths under special directories can be requested by the client without API-key using GET requests
                match method {
                    HttpRequestMethod::GET => Some(request.read_requested_resource(&mut headers)?),
                    _ => return base_error?,
                }
            }
            // The trailing slash at the end is  important, as that ensures there is no extension attached to the "database", meaning that is a file.
            p if p.starts_with("database/") => match config.config_file.database.as_ref() {
                Some(_) => match path {
                    p if p == Path::new("database/tasks.json") => match method {
                        HttpRequestMethod::GET => {
                            Some(request.read_requested_resource(&mut headers)?)
                        }
                        HttpRequestMethod::POST => match request.get_body() {
                            Some(task) => {
                                let mut database = database.lock().await;
                                database.insert(task, DatabaseType::Tasks).await?;
                                String::from("Ok").into()
                            }
                            None => Err("Task not provided in the request body")?,
                        },
                        HttpRequestMethod::DELETE => match request.get_body() {
                            Some(id) => {
                                let mut database: MutexGuard<'_, config::database::Database> =
                                    database.lock().await;
                                database.delete(DatabaseType::Tasks, id).await?;
                                // database.delete(DatabaseType::Tasks);

                                String::from("Ok").into()
                            }
                            None => Err("Id not provided in the request body")?,
                        },
                        _ => return base_error?,
                    },
                    p if p == Path::new("database/users.json") => match method {
                        HttpRequestMethod::GET => {
                            Some(request.read_requested_resource(&mut headers)?)
                        }
                        HttpRequestMethod::POST => Some(match request.get_body() {
                            Some(body) => {
                                let mut database = database.lock().await;
                                database.insert(body, DatabaseType::Users).await?;
                                String::from("Ok")
                            }
                            None => Err("No body in the request")?,
                        }),
                        // Add other methods as needed
                        _ => return base_error?,
                    },
                    _ => return base_error?,
                },
                None => Err("Database not configured in the config file.")?,
            },
            _ => return base_error?,
        };

        headers.add(Cow::from("Connection"), Cow::from("close"));

        let mut response: HttpResponse<'_> = HttpResponse::new(headers, body);

        response.write(&config, &mut writer).await?;

        Ok(())
    }
}
