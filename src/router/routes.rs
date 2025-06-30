use std::{borrow::Cow, error::Error};

use crate::{
    config::{
        database::{collections::ClientUser, DatabaseType, DatabaseUser},
        SpecialDirectories,
    },
    http::{HttpHeaders, HttpRequestMethod},
    router::{
        middleware::Middleware, RouteContext, RouteEntry, RouteHandler, RouteHandlerFuture,
        RouteHandlerResult, RouteResult, RouteTable, RouteTableKey,
    },
};

/// Holds routes that client can get direct access to.
#[derive(Debug)]
pub struct Routes {
    routes: RouteTable,
}

impl Routes {
    pub fn new() -> Self {
        // Creates a new routes with an empty route table.
        Self {
            routes: RouteTable::new(),
        }
    }

    pub fn get_routes(&self) -> &RouteTable {
        // Returns the routes of the router.
        &self.routes
    }

    /// A static route handler that reads the requested resource from the `/public` directory.
    pub fn static_route_handler(
        // Pin<Box<dyn Future<Output = RouteResult<'ctx>> + Send + 'ctx>>;
        ctx: RouteContext,
    ) -> RouteHandlerFuture {
        Box::pin(async move {
            // Extract what we need before any mutable borrows
            let RouteContext {
                request,
                mut response_headers,
                key,
                ..
            } = ctx;

            let body =
                request.read_requested_resource(&mut response_headers, &key.get_prefixed_path())?;

            return Ok(RouteResult::Route(RouteHandlerResult {
                headers: response_headers,
                body,
            }));
        })
    }

    /// Inserts a new route into the route table with the given key and handler.
    ///
    /// If the route already exists, it will panic with a message indicating that the route is already defined.
    pub fn insert(&mut self, key: RouteTableKey, handler: RouteEntry) {
        match handler {
            RouteEntry::Middleware(_) => {
                panic!("Cannot insert a RouteEntry::Middleware into Routes.")
            }
            RouteEntry::Route(_) => {
                if key.get_method().is_none() {
                    panic!("Cannot insert a route handler with no method, please specify a method. None as method is restricted to middleware handlers that run on any method.");
                }

                // let path = key.get_path().to_str().expect("Path should be valid UTF-8");

                // if Middleware::is_path_segment(path) {
                //     let segment_key = RouteTableKey {
                //         path: Middleware::parse_middleware_path(path),
                //         method: key.get_method().clone(),
                //     };

                //     segments.insert(segment_key);
                // }

                self.routes.insert(key, handler);
            }
        }

        // self.routes.insert(key, handler);

        // We should check here if the key does not map to a middleware segment, but that would require for the middleware to be
        // already created, so we would have to create the middleware before the routes.
    }

    /// Statically creates the routes based on the user definitions of the routes with appropriate handlers
    /// for routes and middleware.
    ///
    /// Basically that build API endpoints for the application.
    ///
    /// Automatically collects the routes from the `SpecialDirectories` and inserts them into the route table.
    pub fn create_routes(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Every path in the SpecialDirectories can be routed without authentication using GET method.

        SpecialDirectories::collect()
            .inspect_err(|e: &Box<dyn Error + Send + Sync>| {
                eprintln!("Failed to collect static routes: {}", e);
            })?
            .into_iter()
            .for_each(|key| {
                // This callback would be used to handle the request for the static route.
                // The parameters should live for the duration of the request but the callback function
                // should live for 'static

                self.insert(
                    key,
                    RouteEntry::Route(RouteHandler::new(Self::static_route_handler)),
                )
            });

        // ### Database Routes ###

        // self.insert(
        //     RouteTableKey::new("fkjsdkjfskjf", Some(HttpRequestMethod::DELETE)),
        //     RouteEntry::Middleware(Some(RouteHandler::new(|mut ctx| {
        //         Box::pin(async move {
        //             let headers = ctx.get_response_headers();

        //             headers.add(
        //                 "X-Example-Middleware".into(),
        //                 "Middleware executed for /inexist".into(),
        //             );

        //             Ok(RouteResult::Middleware(MiddlewareHandlerResult { ctx }))
        //         })
        //     }))),
        // );

        // Abstracted route handler that does not exists in the file system.
        // Abstracted path is a path that do not resole to file system if normalized.
        self.insert(
            RouteTableKey::new("/fkjsdkjfskjf", Some(HttpRequestMethod::GET)),
            RouteEntry::Route(RouteHandler::new(|ctx| {
                Box::pin(async move {
                    // First borrow immutably
                    let database = ctx.get_database()?;
                    let database_config = ctx.get_database_config()?;

                    // Then destructure for owned values.
                    let RouteContext {
                        mut response_headers,
                        ..
                    } = ctx;

                    let mut database = database.lock().await;

                    // Example data retrieval from the database.
                    let data = database
                        .select_all(DatabaseType::Tasks, &database_config)
                        .await?;

                    let body = serde_json::to_string(
                        &data
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.serialize()))
                            .collect::<std::collections::HashMap<_, _>>(),
                    )?;

                    response_headers.add(Cow::from("Content-Type"), Cow::from("application/json"));
                    response_headers.add(
                        Cow::from("Content-Length"),
                        Cow::from(body.len().to_string()),
                    );

                    return Ok(RouteResult::Route(RouteHandlerResult {
                        headers: response_headers,
                        body,
                    }));
                })
            })),
        );

        // We should allow GET to the databases but make sure if they not require authentication.
        // If they require we will just check for the, I imagine this the same as with the static routes,
        // although using predefined methods implemented on the Database would be better, as they could allow for
        // more abstraction and maybe we want to leverage that.

        self.insert(
            RouteTableKey::new("database/tasks.json", Some(HttpRequestMethod::GET)),
            RouteEntry::Route(RouteHandler::new(|ctx: RouteContext| {
                Box::pin(async move {
                    let RouteContext {
                        request,
                        mut response_headers,
                        key,
                        // database,
                        ..
                    } = ctx;

                    // If we would want to lay some abstraction on the database we would have "select_all" from the database
                    // and then parse it to the JSON format. Currently we just read the file from the disk.
                    let body = request
                        .read_requested_resource(&mut response_headers, key.get_prefixed_path())?;

                    return Ok(RouteResult::Route(RouteHandlerResult {
                        headers: response_headers,
                        body,
                    }));
                })
            })),
        );

        self.insert(
            RouteTableKey::new("database/users.json", Some(HttpRequestMethod::GET)),
            RouteEntry::Route(RouteHandler::new(|ctx: RouteContext| {
                Box::pin(async move {
                    let RouteContext {
                        request,
                        mut response_headers,
                        key,
                        // database,
                        ..
                    } = ctx;

                    // If we would want to lay some abstraction on the database we would have "select_all" from the database
                    // and then parse it to the JSON format. Currently we just read the file from the disk.
                    let body = request
                        .read_requested_resource(&mut response_headers, key.get_prefixed_path())?;

                    return Ok(RouteResult::Route(RouteHandlerResult {
                        headers: response_headers,
                        body,
                    }));
                })
            })),
        );

        self.insert(
            RouteTableKey::new("database/tasks.json", Some(HttpRequestMethod::POST)),
            RouteEntry::Route(RouteHandler::new(|ctx| {
                Box::pin(async move {
                    // First borrow immutably
                    let database = ctx.get_database()?;

                    // Then destructure for owned values.
                    let RouteContext {
                        request,
                        response_headers,
                        ..
                    } = ctx;

                    let mut database = database.lock().await;

                    if let Some(body) = request.get_body() {
                        database.insert(DatabaseType::Tasks, body).await?;
                    } else {
                        return Err(Box::<dyn Error + Send + Sync>::from("Task cannot be empty"));
                    }

                    return Ok(RouteResult::Route(RouteHandlerResult {
                        headers: response_headers,
                        body: "Task added successfully".to_string(),
                    }));
                })
            })),
        );

        self.insert(
            RouteTableKey::new("database/users.json", Some(HttpRequestMethod::POST)),
            RouteEntry::Route(RouteHandler::new(|ctx| {
                return Box::pin(async move {
                    let database = ctx.get_database()?;

                    let RouteContext {
                        request,
                        response_headers,
                        ..
                    } = ctx;

                    let mut database = database.lock().await;

                    if let Some(body) = request.get_body() {
                        // NOTE: Why it does not work, and what have to be done to make it work?
                        // 1. The body is not of DatabaseUser type after parsing. Data comes from client which does not have full information about the type.
                        //  -> The server has to define those fields.
                        // 2. We have to parse the body to the DatabaseUser first parsing to the type which client sends, that would be statically defined in the route handler,
                        //  -> then we would generate undefined fields, create the DatabaseUser, serialize it to bytes and insert it into the database.
                        // 3. Then we would have solve the problem of cookie headers, as each user_id should map to unique cookie header, as we need the identification
                        //  -> of the user between requests. That would require us to create another collection of `sessions` that would resolve the cookie to the user_id
                        //  -> (cookie can be thought of as session_id).
                        // 4. Additionally we need to make sure the tasks can be inserted only if authenticated, meaning cookie exists and is valid.
                        // 5. User creation should not be buffered in the WAL file and resolved abruptly.

                        let entry = serde_json::from_slice::<ClientUser>(body).map_err(|e| {
                            Box::<dyn Error + Send + Sync>::from(format!(
                                "Failed to parse body: {}",
                                e
                            ))
                        })?;

                        let entry = DatabaseUser::from(entry);
                        database
                            .insert(DatabaseType::Users, &serde_json::to_vec(&entry)?)
                            .await?;
                    } else {
                        return Err(Box::<dyn Error + Send + Sync>::from("Task cannot be empty"));
                    }

                    return Ok(RouteResult::Route(RouteHandlerResult {
                        headers: response_headers,
                        body: "User added successfully".to_string(),
                    }));
                });
            })),
        );

        return Ok(());
    }
}
