pub mod cache;
mod controller;
mod middleware;
mod routes;

use crate::{
    http_response::HttpResponse,
    prelude::*,
    router::cache::{
        OwnedMiddlewareHandlerResult, OwnedRouteContext, OwnedRouteHandlerResult, RouterCache,
        RouterCacheResult,
    },
};

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

use tokio::{net::tcp::OwnedWriteHalf, sync::Mutex};

use crate::{
    config::{Config, SpecialDirectories},
    http::{HttpRequestError, HttpRequestHeaders, HttpRequestMethod, HttpResponseHeaders},
    http_request::HttpRequest,
    router::{
        middleware::{Middleware, MiddlewareHandlerResult},
        routes::Routes,
    },
};

use horrible_database::{Database, collections::DatabaseConfigEntry};

/// The `RouteTable` is a `HashMap` that maps the route key to the route value.
///
/// We are keeping `MiddlewareHandler` there as we are considering that just the special case of the `RouteHandler`,
/// Keeping in the separate struct we would need to allocate a separate
#[derive(Debug)]
pub struct Router {
    routes: Routes,
    middleware: Middleware,
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
        // kind: RouteKeyKind,
    ) -> Self {
        // // First validate, then normalize.
        // if let (RouteKeyKind::Route, None) = (&kind, &method) {
        //     panic!("Cannot create a route table key with no method, please specify a method.");
        // }

        // That would not be necessary if validate_request_target_path would operate on `Path` || `PathBuf` || impl AsRef<Path>.
        let path_str = path
            .as_ref()
            .to_str()
            .expect("Path must be valid UTF-8")
            .to_lowercase();

        // This call is basically for dev purposes, it will disallow us inserting invalid paths, even if the invalid paths
        // would be inserted by the developer defining the RouteTableKey, that would not get matched as the same check runs when we parse
        // the request and would be disallowed if given from the client.
        if let Err(e) = HttpRequestHeaders::validate_request_target_path(&path_str) {
            panic!("Could not validate path: {:?}", e);
        };

        // Validation to how router works, specifically for the middleware paths that has some special characters.
        // decoding special meaning, triggering special behavior.

        // Technically that should only work on middleware paths, when middleware is inserted.
        // If we want to separate this we would have to create a separate constructor for the middleware paths or separate struct.

        // if let RouteKeyKind::Middleware = kind {
        //     if let Err(e) = Middleware::validate_middleware_path(&path_str) {
        //         panic!("Could not validate for middleware path: {:?}", e)
        //     };
        // }

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
    /// Path should be validated and decoded, does not normalize the path.
    ///
    /// Validation runs under `HttpRequestRequestLine::new`, path is decoded in `HttpRequestHeaders::get_request_target_path`
    /// if used in client code, otherwise that is used to .
    // pub fn new_no_validate(
    //     path: impl AsRef<Path>,
    //     method: Option<HttpRequestMethod>,
    //     kind: RouteKeyKind,
    // ) -> Self {
    //     if let (RouteKeyKind::Route, None) = (kind, &method) {
    //         panic!("Cannot create a route table key with no method, please specify a method.");
    //     }

    //     Self {
    //         path: PathBuf::from(path.as_ref()),
    //         method,
    //     }
    // }

    pub fn get_path(&self) -> &Path {
        // Returns the path of the route table key.
        &self.path
    }

    /// Path on the instance are already normalized, this is used to obtain the relative
    /// path to the resource on the server relative to the `/public` directory.
    ///
    /// Should be used for paths pointing to the file system.
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

#[derive(Clone, Debug)]
pub struct RouteContext<'ctx> {
    pub request: HttpRequest<'ctx>,
    pub response_headers: HttpResponseHeaders<'ctx>,
    pub key: &'ctx RouteTableKey,
    pub database: Option<Arc<Mutex<Database>>>,
    pub database_config: Option<DatabaseConfigEntry>, // Config cannot be used here as Config itself contains the RouteTable, that would be a circular reference.
                                                      // Maybe we would have no issues with that as Config is in Arc<Mutex<_>>, but we won't do that.
                                                      // If we would access that field we would have a problem.
}

impl<'ctx> RouteContext<'ctx> {
    pub fn new(
        request: HttpRequest<'ctx>,
        response_headers: HttpResponseHeaders<'ctx>,
        key: &'ctx RouteTableKey,
        database: Option<Arc<Mutex<Database>>>,
        database_config: Option<DatabaseConfigEntry>,
    ) -> Self {
        // We could set the context from the Cache there.

        Self {
            request,
            response_headers,
            key,
            database,
            database_config,
        }
    }

    pub fn into_owned(&self) -> OwnedRouteContext {
        let start = std::time::Instant::now();

        // Converts the `RouteContext` into an `OwnedRouteContext`.
        let c = OwnedRouteContext {
            request: self.request.clone().into_owned(),
            response_headers: self.response_headers.clone().into_owned(),
            key: self.key.clone(),
            database: self.database.clone(),
            database_config: self.database_config.clone(),
        };

        info!(
            "Converted RouteContext to OwnedRouteContext took: {} µs",
            start.elapsed().as_micros()
        );

        return c;
    }

    pub fn get_response_headers(&mut self) -> &mut HttpResponseHeaders<'ctx> {
        // Returns the response headers of the route handler context.
        &mut self.response_headers
    }

    // Returns the key of the route handler context.
    pub fn get_key(&self) -> &RouteTableKey {
        &self.key
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

#[derive(Clone, Debug)]
pub struct RouteHandlerResult<'ctx> {
    pub headers: HttpResponseHeaders<'ctx>,
    // I think we will live it as a String and do not keep it as a Cow<'a, [u8]> as the data in route handlers mostly has to be owned as
    // converting to Cow will create not benefit.
    pub body: Cow<'ctx, str>,
}

impl RouteHandlerResult<'_> {
    pub fn into_owned(&self) -> OwnedRouteHandlerResult {
        let start = std::time::Instant::now();

        // Converts the `RouteHandlerResult` into an `OwnedRouteHandlerResult`.
        let r = OwnedRouteHandlerResult {
            headers: self.headers.clone().into_owned(),
            body: self.body.to_string(),
        };

        info!(
            "Converted RouteHandlerResult to OwnedRouteHandlerResult took: {} µs",
            start.elapsed().as_micros()
        );

        r
    }
}

#[derive(Clone, Debug)]
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

// NOTE: Using 'static here because the closure itself lives for the program duration,
// but it can work with any lifetime 'ctx through the for<'ctx> bound
pub type RouteHandlerClosure =
    Arc<dyn for<'ctx> Fn(RouteContext<'ctx>) -> RouteHandlerFuture<'ctx> + Send + Sync>;
// RouteContext<'ctx>
//  + 'static

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
        // ctx: AnyRouteContext<'ctx>,
        ctx: RouteContext<'ctx>,
    ) -> Result<RouteResult<'ctx>, Box<dyn Error + Send + Sync>> {
        (self.0)(ctx).await
    }
}

impl Router {
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Creates a new router with the given routes and middleware.

        let mut routes = Routes::new();
        routes.create_routes()?;

        let mut middleware = Middleware::new();

        middleware.create_middleware()?;
        middleware.generate_segments(&routes)?;

        Ok(Self { middleware, routes })
    }

    pub fn get_routes(&self) -> &Routes {
        // Returns the routes of the router.
        &self.routes
    }

    pub fn get_routes_mut(&mut self) -> &mut Routes {
        // Returns the mutable routes of the router.
        &mut self.routes
    }

    pub async fn execute_middleware_segment<'ctx>(
        &self,
        ctx: RouteContext<'ctx>,
    ) -> Result<OwnedMiddlewareHandlerResult, Box<dyn Error + Send + Sync>> {
        match self.middleware.get_segments().get(&ctx.get_key()) {
            Ok(RouteEntry::Middleware(Some(handler))) => {
                let k = ctx.get_key().clone();
                let start_time = std::time::Instant::now();

                let result = handler.callback(ctx).await.inspect_err(|e| {
                    error!("Error in middleware segment handler for {k:?} | {:?}", e);
                })?;

                info!(
                    "Middleware segment for path: {:?} took: {} ms",
                    k,
                    start_time.elapsed().as_millis()
                );
                match result {
                    RouteResult::Middleware(MiddlewareHandlerResult { ctx: context }) => {
                        // If the middleware segment exists, we run the middleware for that segment.
                        // We do not want to propagate the error here, as we want to return the context back to the route handler.
                        let start = std::time::Instant::now();

                        let ctx = context.into_owned();

                        info!(
                            "Converting context in Middleware Segment from MiddlewareHandlerResult to OwnedRouteContext took: {}ms",
                            start.elapsed().as_millis()
                        );

                        return Ok(OwnedMiddlewareHandlerResult { ctx });
                    }
                    // This branch would only evaluate if the wrong enum variant is returned from the handler
                    _ => {
                        return Err(Box::from(HttpRequestError {
                            internals: Some(Box::from(
                                "Middleware segment handler should evaluate to RouteResult::Middleware",
                            )),
                            ..Default::default()
                        }));
                    }
                }
            }
            _ => Ok(OwnedMiddlewareHandlerResult {
                ctx: ctx.into_owned(),
            }),
        }
    }

    pub async fn execute_middleware_handler<'ctx>(
        &self,
        ctx: RouteContext<'ctx>,
    ) -> Result<OwnedMiddlewareHandlerResult, Box<dyn Error + Send + Sync>> {
        let key = ctx.get_key().clone();

        match self.middleware.get_routes().get_routes().get(&key) {
            Some(RouteEntry::Middleware(Some(middleware))) => {
                let k = ctx.get_key().clone();

                let start_time = std::time::Instant::now();

                let result = middleware.callback(ctx).await.inspect_err(|e| {
                    error!("Error in middleware handler for {k:?} | {:?}", e);
                })?;

                info!(
                    "Middleware for path: {:?} took: {} ms",
                    k,
                    start_time.elapsed().as_millis()
                );

                match result {
                    RouteResult::Middleware(MiddlewareHandlerResult { ctx: context }) => {
                        let start = std::time::Instant::now();

                        let ctx = context.into_owned();

                        info!(
                            "Converting context in Middleware Handler from MiddlewareHandlerResult to OwnedRouteContext took: {} ms",
                            start.elapsed().as_millis()
                        );

                        return Ok(OwnedMiddlewareHandlerResult { ctx });
                    }
                    // This branch would only evaluate if the wrong enum variant is returned from the handler
                    _ => {
                        return Err(Box::from(HttpRequestError {
                            internals: Some(Box::from(
                                "Middleware handler should evaluate to RouteResult::Middleware",
                            )),
                            ..Default::default()
                        }));
                    }
                }
            }
            _ => Ok(OwnedMiddlewareHandlerResult {
                ctx: ctx.into_owned(),
            }),
        }
    }

    pub async fn execute_middleware<'ctx>(
        &self,
        ctx: RouteContext<'ctx>,
    ) -> Result<OwnedMiddlewareHandlerResult, Box<dyn Error + Send + Sync>> {
        let key = ctx.get_key().clone();

        match (
            RouterCache::middleware_segments().get(&key),
            RouterCache::middleware().get(&key),
        ) {
            (Some(OwnedMiddlewareHandlerResult { ctx: context }), None) => {
                info!("[CACHED] Using cached middleware segment for {key:?}");

                return self.execute_middleware_handler(context.to_borrowed()).await;
            }
            // This is just to log that the segment is also used, if there is context for the route handler, we do not need
            // to save ctx = segment.context as the handler will carry over the changes that happen in the segment.
            (Some(_), Some(result)) => {
                info!("[CACHED] Using cached middleware segment for {key:?}");
                info!("[CACHED] Using cached middleware handler for {key:?}");

                return Ok(result);
            }
            (None, Some(result)) => {
                info!("[CACHED] Using cached middleware handler for {key:?}");

                return Ok(result);
                // return self.execute_middleware_handler(context.to_borrowed()).await;
            }
            (None, None) => {
                let OwnedMiddlewareHandlerResult { ctx } =
                    self.execute_middleware_segment(ctx).await?;
                self.execute_middleware_handler(ctx.to_borrowed()).await
            }
        }
    }

    /// `NOTE`: I am a mistakenly implementing the RouteResult as an enum that could standalone return the result of the middleware handler.
    /// That is not the case as middleware does not produce the body and if the handler does not exists we cannot respond with data.
    /// We will keep the functionality, maybe we will utilize it as it is not a big deal to keep it in the code. But keep in mind
    /// That currently the function returns only the `RouteResult::RouteResult` of type `RouteResult<'ctx>`,
    ///
    /// `NOTE`: Route with defined middleware and undefined handler could only be valid if the middleware is a segment, given that special case
    /// we need to keep the `RouteHandler` as `Option<RouteHandler>` in the `RouteTableValue` struct.
    pub async fn route<'ctx>(
        &self,
        config: &MutexGuard<'_, Config>,
        mut writer: &mut MutexGuard<'_, OwnedWriteHalf>,
        req: HttpRequest<'ctx>,
        res: HttpResponseHeaders<'ctx>,
        // ctx: OwnedRouteContext,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Check if the path matches any of the middleware segments.

        let (path, method) = (req.get_request_target_path()?, req.get_method());

        let key = RouteTableKey {
            path: PathBuf::from(path),
            method: Some(method.clone()),
        };

        // println!("Incoming: {:?}", key);
        info!("Incoming request: #{:?}", key);

        let ctx = RouteContext {
            request: req,
            response_headers: res,
            key: &key,
            database: config.app.get_database(),
            database_config: config.get_database_config().cloned(),
        };

        let routes = self.routes.get_routes();

        let key = ctx.get_key().clone();

        // The route must exist for the middleware segment to run.
        // If the path is invalid, an error will be returned, and the middleware segment should not execute.
        // The same applies to the actual middleware handler—if the route does not exist, the middleware should not run either.

        let route = routes.get(&key).map_err(|message| {
            Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                status_code: 404,
                status_text: "Not Found".to_string(),
                message: Some(message.to_string()),
                ..Default::default()
            })
        })?;

        let OwnedMiddlewareHandlerResult { ctx } = self.execute_middleware(ctx).await?;

        // If the handler exists, we call it with the context and return the `result.

        if let RouteEntry::Route(route) = route {
            match RouterCache::routes().get(&key) {
                Some(RouterCacheResult::RouteResult(result)) => {
                    info!("[CACHED] Using cached route handler for {key:?}");

                    // `.to_borrowed`, despite it's name, does .clone() the body.
                    let RouteHandlerResult { headers, body } = result.to_borrowed();

                    // Technically if something was cached, that it should already contains the default headers.
                    // set_default_headers(&mut headers);

                    // fn from(s: String) -> Cow<'a, str> => Converts a String into an [Owned] variant. No heap allocation is performed, and the string is not copied.

                    let mut response = HttpResponse::new(&headers, Some(body));
                    return response.write(&config, &mut writer).await;
                }
                _ => {
                    let result = route.callback(ctx.to_borrowed()).await?;

                    match result {
                        RouteResult::Route(RouteHandlerResult { headers, body }) => {
                            // crate::tcp_handlers::set_default_headers(&mut headers);

                            let mut response = HttpResponse::new(&headers, Some(body));
                            return response.write(&config, &mut writer).await;
                        }
                        // This branch would only evaluate if the wrong enum variant is returned from the handler
                        _ => {
                            return Err(Box::from(HttpRequestError {
                                internals: Some(Box::from(
                                    "Route handler should evaluate to RouteResult::Route",
                                )),
                                ..Default::default()
                            }));
                        }
                    }
                }
            }
        }

        return Err(Box::<dyn Error + Send + Sync>::from(HttpRequestError {
            status_code: 404,
            status_text: "Not Found".to_string(),
            message: Some(format!(
                "Route not found for path: {:?} with method: {:?}",
                ctx.get_key().path,
                ctx.get_key().method
            )),
            ..Default::default()
        }));

        // TODO: I think we should redirect to a 404 page or something like that.
        // But we need the functionality for that.
    }
}

impl RouteTable {
    pub fn new() -> Self {
        // Creates a new route table.
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

    /// Looks up the `routes` field of the `RouteTable` and returns the `RouteEntry` for the given key.
    ///
    /// Searches for a route with given key, it will try to look up the path as is
    /// and if not found, it will try to suffix with index.html and look it up again. Path is already validated.
    /// Validation takes place in the `HttpRequestHeaders::validate_request_target_path` in `RouteTableKey::new`
    /// and when request from the client in `HttpRequestRequestLine::new`.
    pub fn get(&self, key: &RouteTableKey) -> Result<RouteEntry, Box<dyn Error + Send + Sync>> {
        // Get the route handler for the given key, if it exists.

        // Bat-shit crazy
        let routes = self.get_routes();

        // First match the key as is, we are not prefixing write away as abstracted paths should not be prefixed

        if let Some(value) = routes.get(key) {
            return Ok(value.clone());
        }

        let mut path = PathBuf::from(key.get_path());
        path.push(Config::SERVER_INDEX_PATH);

        // We don't want validation and normalization here.
        let suffixed_path_key = RouteTableKey {
            path: path,
            method: key.method.clone(),
        };

        // Try to match the prefixed key, if the former did not match. This is done for paths
        // pointing to directory in the /public directory resolving to the index.html file in that directory.
        match routes.get(&suffixed_path_key) {
            Some(value) => Ok(value.clone()),
            None => Err(Box::<dyn Error + Send + Sync>::from(format!(
                "Route not found for path: {:?} with method: {:?}",
                key.path, key.method
            ))),
        }
    }

    /// Inserts a new route into the route table with the given key and handler.
    ///
    /// If the route already exists, it will panic with a message indicating that the route is already defined.
    ///
    /// Works as an internal function for the `Middleware` and `Routes` structs.
    fn insert(
        &mut self,
        key: RouteTableKey,
        handler: RouteEntry,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let routes = self.get_routes_mut();

        // We are throwing an error in case the route already exists, but we allowing to overwrite the routes
        // that are in the public directory, but only with the GET method. Since all routes in the public directory
        // have the same default behavior, we want to allow overwriting them.

        // All keys are the one with GET method on it, we can just compare the keys
        let special_directories = SpecialDirectories::collect()?;

        if special_directories.contains(&key) {
            // Guard check, although every key in the special_directories is with GET method,
            if key.method == Some(HttpRequestMethod::GET) {
                routes.insert(key.clone(), handler);

                return Ok(());
            }
        }

        if let Some(_) = routes.insert(key.clone(), handler) {
            panic!(
                "Handler already defined for path: {:?} with method: {:?}",
                key.path, key.method
            );
        }

        Ok(())
    }
}
