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
    use crate::http::{HttpHeaders, HttpResponseHeaders, HttpResponseStartLine};
    use crate::*;
    use http::HttpRequestError;
    use http_response::HttpResponse;
    use std::borrow::Cow;
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
                    // println!("Connection established with: {:?}", socket);

                    let (mut reader, writer) = stream.into_split();

                    let writer = Arc::new(Mutex::new(writer));
                    let config = Arc::clone(&config);

                    let task_error_writer = Arc::clone(&writer);

                    let task = tokio::spawn(async move {
                        let config = config.lock().await;
                        let mut writer = writer.lock().await;

                        if let Err(err) =
                            self::handle_client(&mut reader, &mut writer, &config).await
                        {
                            if let Err(err) =
                                HttpRequestError::send_error_response(&config, &mut writer, err)
                                    .await
                            {
                                eprintln!("Error sending error response: {}", err);
                            };

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
        writer: &mut MutexGuard<'_, OwnedWriteHalf>,
        config: &MutexGuard<'_, Config>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let request: HttpRequest<'_> = HttpRequest::new(&config, reader).await?;
        let mut headers: HttpResponseHeaders<'_> =
            HttpResponseHeaders::new(HttpResponseStartLine::default());

        // If path is invalid and cannot be encoded, that should end the request
        let path = request.get_request_target()?;

        let (method, path) = (request.get_headers().get_method(), path);

        // println!("Requesting: {:?} {}", method, path);

        // This will be executed for every request and try to match paths that should be redirected
        // although the only redirection that we are doing is from http://127.0.0.1:<port> to http://localhost:<port>
        // paths are defined in the config file under 'domain' field, for domains and path redirect in the "paths" field

        // Give back the reference supplied to the function
        if request.redirect_request(&config, writer, &path).await? {
            return Ok(());
        };

        // Run middleware if it exists for the paths
        // path = /database/
        // middleware(request)

        // Very basic middleware to trigger some functionality on certain paths and match the pattern
        // match path {
        //     p if true => {
        //         println!("Middleware executed for path: {:?}", p.components());
        //     }
        //     _ => {}
        // }

        // TODO: Initialization of the Database should be done once, presumably in the middleware when necessary.
        // but it cannot be done once in this format as each DatabaseType requires different initialization

        let database = config.get_database()?;

        let body = match method {
            // This throws an error because the app is making a GET request to the path
            // that does not exists, which is correct by definition
            // NOTE: We should initialize the database only once, or at least at the top,
            // but that tomorrow...
            // GET /database/tasks.json => Database::init() => Give back the control flow to the request initialized \end_middleware
            HttpRequestMethod::GET => Some(request.read_requested_resource(&mut headers)?),
            HttpRequestMethod::POST => {
                // This would return Path not found if the path does not exists
                // If we would want to make custom endpoints without actual path existence
                // then it should be rewritten

                // NOTE: Paths under /database should validate the existence of WAL and database_config only once
                // not to avoid checking the same thing multiple times

                match path {
                    p if p == "/database/tasks.json" => {
                        Some(match config.config_file.database.as_ref() {
                            Some(_) => match request.get_body() {
                                // Some(body) => instance.insert(body).await?,
                                Some(body) => {
                                    let mut database = database.lock().await;
                                    // dbg!(&database);

                                    database.insert(body, DatabaseType::Tasks).await?;

                                    String::from("Ok")
                                }
                                None => Err("No body in the request")?,
                            },
                            None => Err("Database not configured in the config file.")?,
                        })
                    }
                    // p if p == "/database/test" => {
                    //     Some(match config.config_file.database.as_ref() {
                    //         Some(_) => match request.get_body() {
                    //             // Some(body) => instance.insert(body).await?,
                    //             Some(body) => {
                    //                 let mut database = database.lock().await;
                    //                 // dbg!(&database);

                    //                 let entry = database.select_all(DatabaseType::Tasks).await?;
                    //                 println!("Entry: {:?}", entry);

                    //                 String::from("Ok")
                    //             }
                    //             None => Err("No body in the request")?,
                    //         },
                    //         None => Err("Database not configured in the config file.")?,
                    //     })
                    // }
                    _ => {
                        eprintln!("Path does not exists on the server or the method used is unsupported for that path: {:?}", path);

                        return Err(HttpRequestError {
                            status_code: 404,
                            status_text: String::from("Not Found"),
                            message: String::from("Path does not exists on the server or the method used is unsupported for that path").into(),
                            content_type: "text/plain".to_string().into()
                        })?;
                    }
                }
            }
            HttpRequestMethod::DELETE => todo!(),
            HttpRequestMethod::UPDATE => todo!(),
            HttpRequestMethod::PUT => todo!(),
        };

        headers.add(Cow::from("Connection"), Cow::from("close"));

        let mut response: HttpResponse<'_> = HttpResponse::new(headers, body);

        response.write(&config, writer).await?;
        Ok(())
    }
}
