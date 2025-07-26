use std::{borrow::Cow, collections::HashMap, error::Error};

use serde_json::json;

use crate::{
    config::{
        database::{
            collections::{ClientSession, ClientTask, ClientUser, DatabaseSession},
            DatabaseEntryTrait, DatabaseTask, DatabaseUser,
        },
        SpecialDirectories,
    },
    http::{HttpHeaders, HttpRequestError, HttpRequestMethod},
    router::{
        RouteContext, RouteEntry, RouteHandler, RouteHandlerFuture, RouteHandlerResult,
        RouteResult, RouteTable, RouteTableKey,
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
    pub fn insert(
        &mut self,
        key: RouteTableKey,
        handler: RouteEntry,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match handler {
            RouteEntry::Middleware(_) => {
                panic!("Cannot insert a RouteEntry::Middleware into Routes.")
            }
            RouteEntry::Route(_) => {
                if key.get_method().is_none() {
                    panic!("Cannot insert a route handler with no method, please specify a method. None as method is restricted to middleware handlers that run on any method.");
                }

                self.routes.insert(key, handler)
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

        let static_routes =
            SpecialDirectories::collect().inspect_err(|e: &Box<dyn Error + Send + Sync>| {
                eprintln!("Failed to collect static routes: {}", e);
            })?;

        for key in static_routes {
            // This callback would be used to handle the request for the static route.
            // The parameters should live for the duration of the request but the callback function
            // should live for 'static
            self.insert(
                key,
                RouteEntry::Route(RouteHandler::new(Self::static_route_handler)),
            )?;
        }

        // ### Redefined for custom behavior Static Routes ###

        self.insert(
            RouteTableKey::new("/", Some(HttpRequestMethod::GET)),
            RouteEntry::Route(RouteHandler::new(|mut ctx| {
                Box::pin(async move {
                    // We want to flush the database on the load of that route.

                    let database = ctx.get_database()?;
                    let mut database = database.lock().await;

                    database.collections.flush().await?;

                    return Ok(RouteResult::Route(RouteHandlerResult {
                        body: ctx.request.read_requested_resource(
                            &mut ctx.response_headers,
                            ctx.key.get_prefixed_path(),
                        )?,
                        headers: ctx.response_headers,
                    }));
                })
            })),
        )?;

        // ### Database Routes ###

        // Abstracted route handler that does not exists in the file system.
        // Abstracted path is a path that do not resole to file system if normalized.
        self.insert(
            RouteTableKey::new("/api/database/list", Some(HttpRequestMethod::GET)),
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

                    let query = request
                        .get_request_target_query()
                        .collect::<HashMap<_, _>>();

                    let Some(collection_name) = query.get("collection") else {
                        return Err(Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                            status_code: 400,
                            message: Some("Collection name is required".to_string()),
                            content_type: Some(String::from("text/plain")),
                            ..Default::default()
                        }));
                    };

                    // If the collection is specified, we can return the collection data.
                    let mut database = database.lock().await;

                    // That is impossible as we cannot know the type of the collection at runtime.

                    let collection = database.collections.select_all_any(collection_name).await?;

                    // Get the size of the collection if specified in the query. Acts like boolean flag.
                    if let Some(size) = query.get("size") {
                        if let Ok(_) = size.parse::<usize>() {
                            // If the size is specified, we can return the collection data with the size limit.
                            return Ok(RouteResult::Route(RouteHandlerResult {
                                headers: response_headers,
                                body: serde_json::to_string(&json!({
                                    "collection": collection_name,
                                    "size": collection.len().to_string(),
                                }))?,
                            }));
                        }
                    }

                    let body = serde_json::to_string(&collection)?;

                    return Ok(RouteResult::Route(RouteHandlerResult {
                        headers: response_headers,
                        body,
                    }));
                })
            })),
        )?;

        // We should allow GET to the databases but make sure if they not require authentication.
        // If they require we will just check for the, I imagine this the same as with the static routes,
        // although using predefined methods implemented on the Database would be better, as they could allow for
        // more abstraction and maybe we want to leverage that.

        self.insert(
            RouteTableKey::new("/database/tasks.json", Some(HttpRequestMethod::GET)),
            RouteEntry::Route(RouteHandler::new(|ctx: RouteContext| {
                Box::pin(async move {
                    let RouteContext {
                        request,
                        mut response_headers,
                        key,
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
        )?;

        self.insert(
            RouteTableKey::new("/database/users.json", Some(HttpRequestMethod::GET)),
            RouteEntry::Route(RouteHandler::new(|ctx: RouteContext| {
                Box::pin(async move {
                    let database = ctx.get_database()?;
                    let mut database = database.lock().await;

                    let RouteContext {
                        response_headers, ..
                    } = ctx;

                    // If we would want to lay some abstraction on the database we would have "select_all" from the database
                    // and then parse it to the JSON format. Currently we just read the file from the disk.
                    // let body = request
                    // .read_requested_resource(&mut response_headers, key.get_prefixed_path())?;

                    let body = database
                        .collections
                        .select_all::<DatabaseUser, ClientUser>("users")
                        .await?;

                    return Ok(RouteResult::Route(RouteHandlerResult {
                        headers: response_headers,
                        body: serde_json::to_string(&body)?,
                    }));
                })
            })),
        )?;

        self.insert(
            // api/database/tasks/create
            // api/database/tasks/delete?id=123
            // api/database/tasks/get?id=123
            // api/database/tasks/update?id=123
            // api/database/tasks/list?userId=321
            RouteTableKey::new("/database/tasks.json", Some(HttpRequestMethod::POST)),
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
                        let entry = database
                            .collections
                            .insert::<DatabaseTask, ClientTask>(&body.clone())
                            .await?;

                        return Ok(RouteResult::Route(RouteHandlerResult {
                            headers: response_headers,
                            body: DatabaseEntryTrait::serialize(&entry)?,
                        }));
                    }

                    return Err(Box::<dyn Error + Send + Sync>::from("Task cannot be empty"));
                })
            })),
        )?;

        self.insert(
            RouteTableKey::new("/database/tasks.json", Some(HttpRequestMethod::DELETE)),
            RouteEntry::Route(RouteHandler::new(|ctx| {
                Box::pin(async move {
                    let database = ctx.get_database()?;
                    let mut database = database.lock().await;

                    let RouteContext {
                        request,
                        response_headers,
                        ..
                    } = ctx;

                    if let Some(body) = request.get_body().cloned() {
                        let id = String::from_utf8(body).map_err(|_| HttpRequestError {
                            status_code: 400,
                            message: Some("Invalid UTF-8 sequence".into()),
                            ..Default::default()
                        })?;

                        database.collections.delete("tasks", id).await?;

                        return Ok(RouteResult::Route(RouteHandlerResult {
                            headers: response_headers,
                            body: String::new(),
                        }));
                    }

                    return Err(Box::<dyn Error + Send + Sync>::from("Task ID is required"));
                })
            })),
        )?;

        self.insert(
            // api/database/users/create
            // api/database/users/get?
            // ...
            RouteTableKey::new("/database/users.json", Some(HttpRequestMethod::POST)),
            // RouteTableKey::new("database/users.json", Some(HttpRequestMethod::POST)),
            RouteEntry::Route(RouteHandler::new(|ctx| {
                return Box::pin(async move {
                    let database = ctx.get_database()?;

                    let RouteContext {
                        request,
                        mut response_headers,
                        ..
                    } = ctx;

                    let mut database = database.lock().await;

                    if let Some(body) = request.get_body() {
                        // NOTE: Why it does not work, and what have to be done to make it work?
                        // 1. The body is not of DatabaseUser type after parsing. Data comes from client which does not have full information about the type.
                        //  -> The server has to define those fields.
                        // 2. We have to parse the body to the DatabaseUser first parsing to the type which client sends,
                        //  -> then we would generate not client defined fields, instantiate the DatabaseUser, serialize it to bytes and insert it into the database.
                        // 3. Then we would have solve the problem of cookie headers, as each user_id should map to unique cookie header, as we need the identification
                        //  -> of the user between requests. That would require us to create another collection of `sessions` that would resolve the cookie to the user_id
                        //  -> (cookie can be thought of as session_id).
                        // 4. Additionally we need to make sure the tasks can be inserted only if authenticated, meaning cookie exists and is valid.
                        // 5. User creation should not be buffered in the WAL file and resolved abruptly.

                        let entry = database
                            .collections
                            .insert::<DatabaseUser, ClientUser>(&body.clone())
                            .await?;

                        // We could define an endpoint for the session creation, but we can also just create it here.
                        // That is kind of ambiguous, but the API key is of id in the session, and the id is of the userId
                        let session = ClientSession::new(entry.get_api_key(), entry.get_id());

                        database
                            .collections
                            .insert::<DatabaseSession, ClientSession>(&serde_json::to_vec(
                                &session,
                            )?)
                            .await?;

                        database.collections.flush().await?;

                        // Generate a session entry.

                        response_headers.add(
                            Cow::from("Set-Cookie"),
                            format!("sessionId={}", entry.get_api_key()).into(),
                        );

                        return Ok(RouteResult::Route(RouteHandlerResult {
                            headers: response_headers,
                            body: entry.serialize()?,
                        }));
                    } else {
                        return Err(Box::<dyn Error + Send + Sync>::from("Task cannot be empty"));
                    }
                });
            })),
        )?;

        return Ok(());
    }
}
