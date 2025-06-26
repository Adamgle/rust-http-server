use std::{
    borrow::Cow,
    collections::HashMap,
    error::Error,
    future::Future,
    hash::Hash,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use tokio::sync::Mutex;

use crate::{
    config::{
        config_file::DatabaseConfigEntry,
        database::{self, collections::ClientUser, Database, DatabaseType, DatabaseUser},
        Config, SpecialDirectories,
    },
    http::{
        HttpHeaders, HttpRequestError, HttpRequestHeaders, HttpRequestMethod, HttpResponseHeaders,
    },
    http_request::HttpRequest,
    middleware::{Middleware, MiddlewareHandlerResult},
};

// NOTE: Route table does live for the duration of the program, but not the values it is referencing.
// We need to copy that values to put it in the route table because values it is referencing are not
// static and will be wasted from memory after request is done.

// NOTE: Lifetimes are not practically even in this code, as the RouteTable does not have not tied
// the request and response headers to the lifetime of struct, it is independent and those values lives shorter lifetime.

/// The route table is a hash map that maps the route key to the route value.
///
/// We are keeping MiddlewareHandler there as we are considering that just the special case of the RouteHandler,
/// Keeping in the separate struct we would need to allocate a separate
///
#[derive(Debug)]
pub struct Router {
    pub routes: RouteTable,
    pub middleware: Middleware,
}

/// Represents an entry in the route table, which can be either a route handler or a middleware handler.
#[derive(Clone)]
pub enum RouteEntry {
    Route(Arc<RouteHandler>),
    Middleware(Option<Arc<RouteHandler>>),
}

impl std::fmt::Debug for RouteEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteEntry::Route(handler) => write!(f, "Route({:?})", handler),
            RouteEntry::Middleware(Some(handler)) => write!(f, "Middleware({:?})", handler),
            RouteEntry::Middleware(None) => write!(f, "Middleware(None)"),
        }
    }
}

pub struct RouteTable(HashMap<RouteTableKey, RouteEntry>);

impl std::fmt::Debug for RouteTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Custom debug implementation to show the keys of the route table
        let mut keys = self.0.keys().collect::<Vec<_>>();

        // Sort the keys
        keys.sort();

        // I can't sort the HashMap directly, so I will sort the keys and look up the value
        // consequently for sorted keys.

        let mut routes = Vec::<String>::new();

        for key in keys.iter() {
            if let Some(value) = self.0.get(*key) {
                // (key, &**value)
                routes.push(format!("{:?} | {:?}", key, value));
            }
        }

        f.debug_struct("RouteTable")
            .field("routes", &routes)
            .finish()
    }
}

/// Method is optional to support middleware paths that can be run with any method. `None` as a method is invalid for the routes.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct RouteTableKey {
    pub path: PathBuf,
    pub method: Option<HttpRequestMethod>,
}

pub enum RouteKeyKind {
    Route,
    Middleware,
}

impl RouteTableKey {
    /// Creates a new route table key with the given path and method.
    ///
    /// Operate on the decoded path, un-normalized and un-validated. Validates the path.
    ///
    /// `panic!` if path cannot be normalized, so we can change the static definition of the path
    /// as this could be consider a typo in the code.
    pub fn new(
        path: impl AsRef<Path>,
        method: Option<HttpRequestMethod>,
        kind: RouteKeyKind,
    ) -> Self {
        // First validate, then normalize.
        if let RouteKeyKind::Route = kind {
            if method.is_none() {
                panic!("Cannot create a route table key with no method, please specify a method.");
            }
        }

        // That would not be necessary if validate_request_target_path would operate on `Path` || `PathBuf` || impl AsRef<Path>.
        let path_str = path
            .as_ref()
            .to_str()
            .expect("Path must be valid UTF-8")
            .to_lowercase();

        if let Err(e) = HttpRequestHeaders::validate_request_target_path(&path_str) {
            panic!("Could not validate path: {:?}", e);
        };

        // Validation to how router works, specifically for the middleware paths that has some special characters.
        // decoding special meaning, triggering special behavior.

        // Technically that should only work on middleware paths, when middleware is inserted.
        // If we want to separate this we would have to create a separate constructor for the middleware paths or separate struct.

        if let RouteKeyKind::Middleware = kind {
            if let Err(e) = Middleware::validate_middleware_path(&path_str) {
                panic!("Could not validate for middleware path: {:?}", e)
            };
        }

        match HttpRequestHeaders::normalize_path(&path_str) {
            Ok(path) => Self {
                path: PathBuf::from(path),
                method,
            },
            Err(message) => {
                panic!(
                    "Could not normalize path: {:?}, error: {}",
                    path_str, message
                );
            }
        }

        // If we get the abstracted path that does not exist in the file system, how would we handle normalization?
        //  -> abstracted paths should not be normalized, as they are not real paths, but here we are normalizing everything.
        //  -> Normalizing every path also creates a problem with the segments, because then the path cannot be easily checked
        //  -> if it starts with the appropriate prefix.
        // QUESTION: When should we normalize then?
        //  -> Surely when we are requesting the real path from the file system. Like in read_requested_resource, that gets raw bytes of file using GET.
        //  -> Maybe we should try to resolve the path in specific order. We know that we have:
        //  -> - paths that are abstracted which should not be normalized,
        //  -> - paths in file system, that could be of (all of those has to exist in the file system):
        //  ->  - given as a path with extension, off which:
        //          - the extension could be mapped to SpecializedDirectories
        //          - the extension could not be mapped and then the path is not further prefixed with the SpecialDirectories
        //  ->  - paths that are given as a path without extension that currently are prefixed with the SpecialDirectories::Pages and suffixed with `index.html`

        // The problem with abstracted paths is that in current design they would be prefixed with the `SpecialDirectories::Pages` and suffixed with `index.html`
        // because they are semantically the same, a path without extension without a file portion, currently we assume
        // that it is a directory and try to find the index.html in that directory under /pages
        // We need to first try to resolve the path literally in the router and then try to normalize it if not found and lookup again.
    }

    /// Normalizes the path, omits the validation of the `path`.
    ///
    /// Path is validated and decoded, but not normalized.
    ///
    /// Validation runs under `HttpRequestRequestLine::new`, path is decoded in `HttpRequestHeaders::get_request_target_path`.
    ///
    pub fn new_no_validate(
        path: impl AsRef<Path>,
        method: Option<HttpRequestMethod>,
        kind: RouteKeyKind,
    ) -> Self {
        if let RouteKeyKind::Route = kind {
            if method.is_none() {
                panic!("Cannot create a route table key with no method, please specify a method.");
            }
        }

        // let path = HttpRequestHeaders::normalize_path(
        //     &path
        //         .as_ref()
        //         .to_str()
        //         .ok_or("Path must be valid UTF-8")?
        //         .to_lowercase(),
        // )?;

        // Ok(Self(PathBuf::from(path), method))
        Self {
            path: PathBuf::from(path.as_ref()),
            method,
        }
    }

    pub fn get_path(&self) -> &Path {
        // Returns the path of the route table key.
        &self.path
    }

    /// Path on the instance are already normalized, this is used to obtain the relative
    /// path to the resource on the server relative to the `/public` directory.
    pub fn get_prefixed_path(&self) -> PathBuf {
        let path_str = self.get_path().to_str().expect("Path must be valid UTF-8");
        let prefixed_path =
            HttpRequestHeaders::prefix_path(path_str).expect("Could not normalize path");

        PathBuf::from(prefixed_path)
    }

    pub fn get_method(&self) -> &Option<HttpRequestMethod> {
        // Returns the method of the route table key.
        &self.method
    }

    pub fn get_path_mut(&mut self) -> &mut PathBuf {
        // Returns a mutable reference to the path of the route table key.
        &mut self.path
    }
}

impl std::fmt::Debug for RouteTableKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Create a path string representation for more readable output
        let path_str = self.path.to_string_lossy();

        // Format the method more nicely
        let method_str = match &self.method {
            Some(method) => format!("{:?}", method),
            None => "ANY".to_string(),
        };

        // Write it as "PATH [METHOD]" format for more compact representation
        write!(f, "[{}] {}", method_str, path_str)
    }
}

/// Context for the route handler that takes a reference `HttpRequest`, a mutable reference to `HttpResponseHeaders, and a
/// reference to `RouteTableKey`.
///
/// NOTE: The lifetimes here are a bit tricky. The `HttpRequest` and `HttpResponseHeaders` are tied to the request lifecycle.
/// `RouteTableKey` even though is 'static in lifetime in the `RouteTable` it is not static in the parameters of the route handler
/// as it is a reference to the key built in the `handle_client` entry point.

#[derive(Debug)]
pub struct RouteContext<'ctx> {
    pub request: &'ctx HttpRequest<'ctx>,
    pub response_headers: HttpResponseHeaders<'ctx>,
    pub key: &'ctx RouteTableKey,
    pub database: Option<Arc<Mutex<Database>>>,
    pub database_config: Option<DatabaseConfigEntry>, // Config cannot be used here as Config itself contains the RouteTable, that would be a circular reference.
                                                      // Maybe we would have no issues with that as Config is in Arc<Mutex<_>>, but we won't do that.
                                                      // If we would access that field we would have a problem.
}

impl<'ctx> RouteContext<'ctx> {
    pub fn new(
        request: &'ctx HttpRequest<'ctx>,
        response_headers: HttpResponseHeaders<'ctx>,
        key: &'ctx RouteTableKey,
        database: Option<Arc<Mutex<Database>>>,
        database_config: Option<DatabaseConfigEntry>,
    ) -> Self {
        Self {
            request,
            response_headers,
            key,
            database,
            database_config,
        }
    }

    pub fn get_request(&self) -> &HttpRequest<'ctx> {
        // Returns the request of the route handler context.
        self.request
    }

    pub fn get_response_headers(&mut self) -> &mut HttpResponseHeaders<'ctx> {
        // Returns the response headers of the route handler context.
        &mut self.response_headers
    }

    // Returns the key of the route handler context.
    pub fn get_key(&self) -> &RouteTableKey {
        self.key
    }

    pub fn get_database(&self) -> Result<Arc<Mutex<Database>>, Box<dyn Error + Send + Sync>> {
        // Returns the database of the route handler context.
        // Clones the Arc reference, cheap
        self.database
            .clone()
            .ok_or("Database is not initialized in the route handler context".into())
    }

    /// That would only return `None` if the `Database` is also `None`, if there is `database_config` there has to be `Database`,
    /// if there is `Database` there has to be `database_config`.
    pub fn get_database_config(&self) -> Result<DatabaseConfigEntry, Box<dyn Error + Send + Sync>> {
        // Returns the database config of the route handler context.
        // Clones the Arc reference, cheap
        self.database_config
            .clone()
            .ok_or("Database config is not initialized in the route handler context".into())
    }
}

/// Take an owned version of headers that was previously moved from `handle_client` and the result of the
/// request consisting of the body.
///
/// Applies changes to headers as defined in the handler for a given path.
pub struct RouteHandlerResult<'ctx> {
    pub headers: HttpResponseHeaders<'ctx>,
    pub body: String,
}

pub enum RouteResult<'ctx> {
    Route(RouteHandlerResult<'ctx>),
    Middleware(MiddlewareHandlerResult<'ctx>),
}

// UPDATE: Callback cannot live for 'static as the Context gets moved in to a closure
// and then lifetime it utilizes would become invariant. That means a lifetime of context
// would have to be the same as the lifetime of 'static, but Context has lifetime "for all 'ctx".
// We need to pass generic lifetime from the RouteHandlerClosure to use the same exact lifetime as there declared.
pub type RouteHandlerFuture<'ctx> = Pin<
    Box<dyn Future<Output = Result<RouteResult<'ctx>, Box<dyn Error + Send + Sync>>> + Send + 'ctx>,
>;

// TODO: The struct of RouteHandlerValue is already behind Arc, check how to avoid one of the Arc's.
// A closure of the route handler

// NOTE: Check if that 'static fits there, as of my logic, closure is computed at runtime and lives for the duration of the program,
// so it should be 'static, but maybe I am wrong.
pub type RouteHandlerClosure =
    Arc<dyn for<'ctx> Fn(RouteContext<'ctx>) -> RouteHandlerFuture<'ctx> + Send + Sync + 'static>;

/// The idea is that the `RouteHandler` being a function pointer inside a closure stored in the `Arc` is valid for the duration of the program,
/// and can be referenced via multiple async tasks. Only the parameters `RouteHandlerContext` passed to the handler
/// are changing with each request and we make sure to not store that references in the routing table.
//
// NOTE: We wrap the function pointer in the `Arc` inside the `RouteTable` as we want to allow multiple tasks to access
// the same `RouteHandler`, not only the function pointer if we would want to lay some abstraction onto that handler.
#[derive(Clone)]
pub struct RouteHandler(RouteHandlerClosure);

impl std::fmt::Debug for RouteHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Custom debug implementation to show the function pointer
        f.debug_struct("RouteHandler")
            .field("handler", &Arc::as_ptr(&self.0))
            .finish()
    }
}

impl RouteHandler {
    pub fn new<F>(handler: F) -> Arc<Self>
    where
        F: Send + Sync + 'static,
        F: for<'ctx> Fn(RouteContext<'ctx>) -> RouteHandlerFuture<'ctx>,
    {
        Arc::new(Self(Arc::new(handler)))
    }

    /// NOTE: The function that is called inside the callback is not async itself, but when called with
    /// callback it would be. This is due to how RouteHandler is initialized, that you can pass a function pointer
    /// that would coerced to an async function.
    ///
    /// Calls the function pointer with ctx.
    pub async fn callback<'ctx>(
        &self,
        ctx: RouteContext<'ctx>,
    ) -> Result<RouteResult<'ctx>, Box<dyn Error + Send + Sync>> {
        (self.0)(ctx).await
    }

    /// `NOTE`: Handlers do not have to be declared there.
    ///
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
}

impl Router {
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Creates a new router with the given routes and middleware.
        let routes = RouteTable::create_routes()?;

        Ok(Self {
            middleware: Middleware::new(&routes)?,
            routes,
        })
    }

    pub fn get_routes(&self) -> &RouteTable {
        // Returns the routes of the router.
        &self.routes
    }

    pub fn get_routes_mut(&mut self) -> &mut RouteTable {
        // Returns the mutable routes of the router.
        &mut self.routes
    }

    pub fn get_middleware_routes(&self) -> &RouteTable {
        // Returns the middleware of the router.
        &self.middleware.routes
    }

    pub fn get_middleware_segments(&self) -> &HashMap<RouteTableKey, RouteEntry> {
        // Returns the middleware segments of the router.
        &self.middleware.segments
    }

    /// `NOTE`: I am a mistake implementing the RouteResult as an enum that could return standalone the result of the middleware handler.
    /// That is not the case as middleware does not produce the body and if the handler does not exists, but cannot respond with data.
    /// We will keep the functionality, maybe we will utilize it as it is not a big deal to keep it in the code. But keep in mind
    /// That currently the function returns only the `RouteResult::RouteResult` of type `RouteResult<'ctx>`,
    ///
    /// `NOTE`: Route with defined middleware and undefined handler could only be valid if the middleware is a segment, given that special case
    /// we need to keep the `RouteHandler` as `Option<RouteHandler>` in the `RouteTableValue` struct.
    pub async fn route<'ctx>(
        &self,
        mut ctx: RouteContext<'ctx>,
        // RouteResult<'ctx>
    ) -> Result<RouteResult<'ctx>, Box<dyn Error + Send + Sync>> {
        // Check if the path matches any of the middleware segments.

        // Route has to exist for middleware segment to run, as if not, if path is given as invalid there, that would just return an error,
        // but despite that middleware segment could run.
        let route = self.routes.get(ctx.get_key()).map_err(|message| {
            Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                status_code: 404,
                status_text: "Not Found".to_string(),
                message: Some(message.to_string()),
                ..Default::default()
            })
        })?;

        if let Some(RouteEntry::Middleware(Some(handler))) =
            self.get_middleware_segments().get(ctx.get_key())
        {
            let result = handler.callback(ctx).await?;

            match result {
                RouteResult::Middleware(MiddlewareHandlerResult { ctx: context }) => {
                    // If the middleware segment exists, we run the middleware for that segment.
                    // We do not want to propagate the error here, as we want to return the context back to the route handler.
                    ctx = context;
                }
                // This branch would only evaluate if the wrong enum variant is returned from the handler
                _ => {
                    return Err(Box::from(HttpRequestError {
                        internals: Some(Box::from(
                            "Middleware segment handler should evaluate to RouteResult::Middleware",
                        )),
                        ..Default::default()
                    }))
                } // _ => unreachable!("Middleware segment handler should evaluate to RouteResult::Middleware"),
            }

            // If the segment exists, we run the middleware for that segment.
            // We do not want to propagate the error here, as we want to return the context back to the route handler.
        }

        if let Ok(RouteEntry::Middleware(Some(middleware))) =
            self.get_middleware_routes().get(ctx.get_key())
        {
            let result = middleware.callback(ctx).await?;

            match result {
                RouteResult::Middleware(MiddlewareHandlerResult { ctx: context }) => ctx = context,
                // This branch would only evaluate if the wrong enum variant is returned from the handler
                _ => {
                    return Err(Box::from(HttpRequestError {
                        internals: Some(Box::from(
                            "Middleware handler should evaluate to RouteResult::Middleware",
                        )),
                        ..Default::default()
                    }))
                } // _ => unreachable!("Middleware handler should evaluate to RouteResult::Middleware"),
            }
        }

        // If the handler exists, we call it with the context and return the result.

        if let RouteEntry::Route(route) = route {
            // If the route exists, we run the handler for the path.
            // We do not want to propagate the error here, as we want to return the context back to the route handler.
            let result = route.callback(ctx).await?;

            match result {
                RouteResult::Route(route_result) => return Ok(RouteResult::Route(route_result)),
                // This branch would only evaluate if the wrong enum variant is returned from the handler
                _ => {
                    return Err(Box::from(HttpRequestError {
                        internals: Some(Box::from(
                            "Route handler should evaluate to RouteResult::Route",
                        )),
                        ..Default::default()
                    }))
                } // _ => unreachable!("Route handler should evaluate to RouteResult::Route"),
            }
        }

        return Err(Box::<dyn Error + Send + Sync>::from(HttpRequestError {
            status_code: 404,
            status_text: "Not Found".to_string(),
            message: Some(format!(
                "Route not found for path: {:?} with method: {:?}",
                ctx.get_key().get_path(),
                ctx.get_key().get_method()
            )),
            ..Default::default()
        }));

        // return Ok(RouteResult::Route(handler.callback(ctx).await?));

        // match (handler, middleware) {
        //     // Middleware but no handler, we run the middleware return the ctx.
        //     // UPDATE: That is not a valid state, as we should always have a handler for the path.
        //     // (None, Some(middleware)) => {
        //     //     let result = middleware.callback(ctx).await?;
        //     //
        //     //     return Ok(RouteResult::MiddlewareResult(result));
        //     // }

        //     // Handle exists, despite the middleware, return the result of the handler.
        //     (Some(handler), middleware) => {
        //         // Check if the middleware exists, if it does, we run it, update the ctx.

        //         if let Some(middleware) = middleware {
        //             ctx = middleware.callback(ctx).await?.ctx;
        //         }

        //         // If the handler exists, we call it with the context and return the result.

        //         return Ok(RouteResult::Route(handler.callback(ctx).await?));

        //         // Run the handler for the path.
        //     }
        //     _ => {
        // return Err(Box::<dyn Error + Send + Sync>::from(HttpRequestError {
        //     status_code: 404,
        //     status_text: "Not Found".to_string(),
        //     message: Some(format!(
        //         "Route not found for path: {:?} with method: {:?}",
        //         ctx.get_key().get_path(),
        //         ctx.get_key().get_method()
        //     )),
        //     ..Default::default()
        // }))
        //     }
        // };

        // TODO: I think we should redirect to a 404 page or something like that.
        // But we need the functionality for that.
    }
}

impl RouteTable {
    pub fn new() -> Self {
        // Creates a new route table.
        // Ok(Self::create_
        Self(HashMap::<RouteTableKey, RouteEntry>::new())
    }

    pub fn get_routes(&self) -> &HashMap<RouteTableKey, RouteEntry> {
        // Returns the routes in the route table.
        &self.0
    }

    pub fn get_routes_mut(&mut self) -> &mut HashMap<RouteTableKey, RouteEntry> {
        // Returns the mutable routes in the route table.

        &mut self.0
    }

    pub fn insert(&mut self, key: RouteTableKey, handler: RouteEntry) {
        if let Some(_) = self.get_routes_mut().insert(key.clone(), handler) {
            panic!(
                "Route already defined for path: {:?} with method: {:?}",
                key.get_path(),
                key.get_method()
            );
        }
    }

    /// Searches for a route with given key, it will try to look up the path as is
    /// and if not found, it will try to suffix with index.html and look it up again. Path is already validated.
    /// Validation takes place in the `HttpRequestHeaders::validate_request_target_path` in `RouteTableKey::new`
    /// and when request from the client in `HttpRequestRequestLine::new`.
    pub fn get(&self, key: &RouteTableKey) -> Result<RouteEntry, Box<dyn Error + Send + Sync>> {
        // Get the route handler for the given key, if it exists.

        let routes = self.get_routes();

        // First match the key as is, we are not prefixing write away as abstracted paths should not be prefixed

        if let Some(value) = routes.get(key) {
            return Ok(value.clone());
        }

        let path = key.get_path().to_str().ok_or_else(|| {
            Box::<dyn Error + Send + Sync>::from(format!(
                "Path {:?} is not valid UTF-8",
                key.get_path()
            ))
        })?;

        // We are not using `prefix_path` as it would prefix with SpecialDirectories::Pages and suffix with `index.html`,
        // but we just want to suffix with the root file.
        // Prefix with INDEX_PATH => index.html
        let mut path = PathBuf::from(path);
        path.push(Config::SERVER_INDEX_PATH);

        let suffixed_path =
            RouteTableKey::new_no_validate(path, key.get_method().clone(), RouteKeyKind::Route);

        // Try to match the prefixed key, if the former did not match. This is done for paths
        // pointing to directory in the /public directory resolving to the index.html file in that directory.
        match routes.get(&suffixed_path) {
            Some(value) => Ok(value.clone()),
            None => Err(Box::<dyn Error + Send + Sync>::from(format!(
                "Route not found for path: {:?} with method: {:?}",
                key.get_path(),
                key.get_method()
            ))),
        }
    }

    /// Statically creates the routes based on the user definitions of the routes with appropriate handlers
    /// for routes and middleware.
    ///
    /// Automatically collects the routes from the `SpecialDirectories` and inserts them into the route table.
    pub fn create_routes() -> Result<Self, Box<dyn Error + Send + Sync>> {
        // We have the routes cached in the file that is composed in runtime and parsed to some context at startup.
        // We check if the path exists the cached routes or is that a new route that we have defined in the code in that function.

        let mut routes = RouteTable::new();

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

                routes.insert(
                    key,
                    RouteEntry::Route(RouteHandler::new(RouteHandler::static_route_handler)),
                )
            });

        // Populates the middleware paths with handlers

        // ### Database Routes ###

        // Abstracted route handler that does not exists in the file system.
        // Abstracted path is a path that do not resole to file system if normalized.
        routes.insert(
            RouteTableKey::new(
                "/message",
                Some(HttpRequestMethod::GET),
                RouteKeyKind::Route,
            ),
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

        routes.insert(
            RouteTableKey::new(
                "database/tasks.json",
                Some(HttpRequestMethod::GET),
                RouteKeyKind::Route,
            ),
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

        routes.insert(
            RouteTableKey::new(
                "database/tasks.json",
                Some(HttpRequestMethod::POST),
                RouteKeyKind::Route,
            ),
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

        routes.insert(
            RouteTableKey::new(
                "database/users.json",
                Some(HttpRequestMethod::POST),
                RouteKeyKind::Route,
            ),
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

                        // NOTE: That is vulnerable to mistakes, we are defining the same fields as they are already defined.

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

        // #####

        // println!("{:#?}", routes);

        Ok(routes)
    }
}
