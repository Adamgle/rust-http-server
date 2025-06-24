use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    error::Error,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use percent_encoding::{AsciiSet, CONTROLS};
use strum::IntoEnumIterator;
use tokio::sync::Mutex;

use crate::{
    config::{
        config_file::DatabaseConfigEntry,
        database::{Database, DatabaseType},
        SpecialDirectories,
    },
    http::{
        HttpHeaders, HttpRequestError, HttpRequestHeaders, HttpRequestMethod, HttpResponseHeaders,
    },
    http_request::HttpRequest,
    middleware::{Middleware, MiddlewareHandler, MiddlewareHandlerResult, PATH_SEGMENT},
};

// NOTE: Route table does live for the duration of the program, but not the values it is referencing.
// whatever we put in the route table is valid for static, but not the values it is referencing.
// We need to copy that values to put it in the route table because values it is referencing are not
// static and will be wasted from memory after request is done.

// NOTE: Lifetimes are not practically even in this code, as the RouteTable does not have not tied
// the request and response headers to the lifetime of struct, it is independent and those values lives shorter lifetime.

// const FRAGMENT: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'<').add(b'>').add(b'`');

pub const PATH_ENCODING_SET: &AsciiSet = &CONTROLS
    .add(b' ') // space
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub struct RouteTable(HashMap<RouteTableKey, Arc<RouteTableValue>>);

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

/// Consists of a route handler and a middleware handler, both wrapped in an `Arc` to allow shared ownership.
///
/// That would technically waste some memory as I suspect that most path would not have it's corresponding middleware handler,
/// and paths that are strictly a middleware handler would not have a route handler. But the pointer is just 8 bytes,
/// so who cares. That is safer and easier to work with, because other way we would have to allocate a separate table for middleware.
pub struct RouteTableValue(Option<RouteHandler>, Option<MiddlewareHandler>);

impl RouteTableValue {
    pub fn new(handler: Option<RouteHandler>, middleware: Option<MiddlewareHandler>) -> Arc<Self> {
        // Creates a new route table value with the given handler and middleware.
        // Self(Arc::new((handler, middleware)))
        Arc::new(Self(handler, middleware))
    }

    pub fn get_handler(&self) -> Option<&RouteHandler> {
        // Returns the route handler if it exists.
        // self.0 .0.as_ref()
        self.0.as_ref()
    }

    pub fn get_middleware(&self) -> Option<&MiddlewareHandler> {
        // Returns the middleware handler if it exists.
        self.1.as_ref()
    }
}

impl std::fmt::Debug for RouteTableValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Handler: {} | Middleware: {}",
            self.get_handler()
                .map_or("None".to_string(), |_| "Some()".to_string()),
            self.get_middleware()
                .map_or("None".to_string(), |_| "Some()".to_string())
        )
    }
}

/// Routing table lives for the whole lifetime of the server, since path is a `static` lifetime.
///
/// Method is optional to support middleware paths that can be run with any method.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]

pub struct RouteTableKey(pub PathBuf, pub Option<HttpRequestMethod>);

impl RouteTableKey {
    /// Creates a new route table key with the given path and method.
    ///
    /// Operate on the decoded path, un-normalized and un-validated. Validates the path.
    ///
    /// `panic!` if path cannot be normalized, so we can change the static definition of the path
    /// as this could be consider a typo in the code.
    pub fn new(path: impl AsRef<Path>, method: Option<HttpRequestMethod>) -> Self {
        // First validate, then normalize.

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
        if let Err(e) = Middleware::validate_middleware_path(&path_str) {
            panic!("Could not validate for middleware path: {:?}", e)
        };

        match HttpRequestHeaders::normalize_path(&path_str) {
            Ok(path) => Self(PathBuf::from(path), method),
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

    /// Omits the validation of the `path` as it already is validated while parsing http request.
    ///
    /// Path is validated and decoded, but not normalized.
    ///
    /// Validation runs under `HttpRequestRequestLine::new`, path is decoded in `HttpRequestHeaders::get_request_target_path`.
    ///
    pub fn new_no_validate(path: impl AsRef<Path>, method: Option<HttpRequestMethod>) -> Self {
        Self(path.as_ref().to_path_buf(), method)
    }

    pub fn get_path(&self) -> &Path {
        // Returns the path of the route table key.
        &self.0
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
        &self.1
    }

    pub fn get_path_mut(&mut self) -> &mut PathBuf {
        // Returns a mutable reference to the path of the route table key.
        &mut self.0
    }

    /// Middleware paths could have can have special characters that are used when resolving a path.
    ///
    // NOTE:  Functionality can grow so we are implementing a method for that.
    pub fn parse_middleware_path(&self) -> &Path {
        // Parses the middleware path by removing the leading `:` segment if it exists.
        // This is used to normalize the path for middleware handling.

        let path = self.get_path().to_str().expect("Path must be valid UTF-8");

        // That is stupid, but I want to use the same piece of code that does the same logic
        // because if we would change the segment recognition logic, we would have to change it in two places.

        if Middleware::is_path_segment(&path) {
            // safe to unwrap as we checked if the path starts with `:`
            return Path::new(path.strip_prefix(PATH_SEGMENT).unwrap());
        }

        return Path::new(path);
    }
}
impl std::fmt::Debug for RouteTableKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Create a path string representation for more readable output
        let path_str = self.0.to_string_lossy();

        // Format the method more nicely
        let method_str = match &self.1 {
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
pub struct RouteHandlerContext<'ctx> {
    pub request: &'ctx HttpRequest<'ctx>,
    pub response_headers: HttpResponseHeaders<'ctx>,
    pub key: &'ctx RouteTableKey,
    pub database: Option<Arc<Mutex<Database>>>,
    pub database_config: Option<DatabaseConfigEntry>, // Config cannot be used here as Config itself contains the RouteTable, that would be a circular reference.
                                                      // Maybe we would have no issues with that as Config is in Arc<Mutex<_>>, but we won't do that.
                                                      // If we would access that field we would have a problem.
}

// impl<'ctx> RouteResult<'ctx> for RouteHandlerContext<'ctx> {
//     fn as_any(&self) -> &(dyn Any + 'ctx) {
//         self
//     }
// }

impl<'ctx> RouteHandlerContext<'ctx> {
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

// pub trait RouteResult<'ctx>: 'ctx {
//     fn as_any(&self) -> &(dyn Any + 'ctx);
// }

pub enum RouteResult<'ctx> {
    RouteResult(RouteHandlerResult<'ctx>),
    MiddlewareResult(MiddlewareHandlerResult<'ctx>),
}

/// Take an owned version of headers that was previously moved from `handle_client` and the result of the
/// request consisting of the body.
///
/// Applies changes to headers as defined in the handler for a given path.
pub struct RouteHandlerResult<'ctx> {
    pub headers: HttpResponseHeaders<'ctx>,
    pub body: String,
}

// UPDATE: Callback cannot live for 'static as the Context gets moved in to a closure
// and then lifetime it utilizes would become invariant. That means a lifetime of context
// would have to be the same as the lifetime of 'static, but Context has lifetime "for all 'ctx".
// We need to pass generic lifetime from the RouteHandlerClosure to use the same exact lifetime as there declared.
type RouteHandlerFuture<'ctx> = Pin<
    Box<
        dyn Future<Output = Result<RouteHandlerResult<'ctx>, Box<dyn Error + Send + Sync>>>
            + Send
            + 'ctx,
    >,
>;

// TODO: The struct of RouteHandlerValue is already behind Arc, check how to avoid one of the Arc's.
// A closure of the route handler

// NOTE: Check if that 'static fits there, as of my logic, closure is computed at runtime and lives for the duration of the program,
// so it should be 'static, but maybe I am wrong.
type RouteHandlerClosure = Arc<
    dyn for<'ctx> Fn(RouteHandlerContext<'ctx>) -> RouteHandlerFuture<'ctx> + Send + Sync + 'static,
>;

/// A closure enclosing a function pointer that can be called with a `RouteHandlerContext`.
///
/// The idea is that the `RouteHandler` being a function pointer inside a closure stored in the `Arc` is valid for the duration of the program,
/// and can be referenced via multiple async tasks. Only the parameters `RouteHandlerContext` passed to the handler
/// are changing with each request and we make sure to not store that references in the routing table.
//
// NOTE: We wrap the function pointer in the `Arc` inside the `RouteTable` as we want to allow multiple tasks to access
// the same `RouteHandler`, not only the function pointer if we would want to lay some abstraction onto that handler.
#[derive(Clone)]
pub struct RouteHandler(RouteHandlerClosure);

impl RouteHandler {
    pub fn new(handler: fn(RouteHandlerContext) -> RouteHandlerFuture) -> Self {
        let c: RouteHandlerClosure =
            Arc::new(move |ctx: RouteHandlerContext| Box::pin(handler(ctx)));

        Self(c)
    }

    /// NOTE: The function that is called inside the callback is not async itself, but when called with
    /// callback it would be. This is due to how RouteHandler is initialized, that you can pass a function pointer
    /// that would coerced to an async function.
    ///
    /// Calls the function pointer with ctx.
    pub async fn callback<'ctx>(
        &self,
        ctx: RouteHandlerContext<'ctx>,
    ) -> Result<RouteHandlerResult<'ctx>, Box<dyn Error + Send + Sync>> {
        (self.0)(ctx).await
    }

    /// A static route handler that reads the requested resource from the `/public` directory.
    pub fn static_route_handler(
        // Pin<Box<dyn Future<Output = RouteHandlerResult<'ctx>> + Send + 'ctx>>;
        ctx: RouteHandlerContext,
    ) -> RouteHandlerFuture {
        Box::pin(async move {
            // Extract what we need before any mutable borrows
            let RouteHandlerContext {
                request,
                mut response_headers,
                key,
                ..
            } = ctx;

            let body =
                request.read_requested_resource(&mut response_headers, &key.get_prefixed_path())?;

            return Ok(RouteHandlerResult {
                headers: response_headers,
                body,
            });
        })
    }
}

impl RouteTable {
    pub fn new() -> Self {
        // Creates a new empty route table.
        Self(HashMap::new())
    }

    pub fn get_routes(&self) -> &HashMap<RouteTableKey, Arc<RouteTableValue>> {
        // Returns the routes in the route table.
        &self.0
    }

    pub fn get_routes_mut(&mut self) -> &mut HashMap<RouteTableKey, Arc<RouteTableValue>> {
        // Returns the mutable routes in the route table.
        &mut self.0
    }

    pub fn insert_handler(&mut self, key: RouteTableKey, handler: RouteHandler) {
        let (method, path) = (key.get_method(), key.0.clone());

        if let None = method {
            // If the method is ANY, we panic as that is not allowed.
            panic!(
                "Cannot insert a route with ANY method for path: {:?}, please specify a method.",
                path
            );
        }

        // let mut insert_handler_closure = |key: RouteTableKey, handler: RouteHandler| {
        match self
            .get(&key)
            .map(|v| (v.get_handler().cloned(), v.get_middleware().cloned()))
        {
            // Route exists with both RouteHandler and MiddlewareHandler — panic duplicate
            Ok((Some(_), _)) => {
                panic!(
                    "Route already defined for path: {:?} with method: {:?}",
                    path, method
                );
            }
            // Middleware exists but no RouteHandler — insert new RouteHandler while preserving middleware
            Ok((None, Some(middleware))) => {
                let middleware = middleware.clone();

                self.get_routes_mut()
                    .insert(key, RouteTableValue::new(Some(handler), Some(middleware)));
            }
            // No route exists or no handlers — insert new RouteHandler
            // NOTE: That would disregard the error for the result
            _ => {
                self.get_routes_mut()
                    .insert(key, RouteTableValue::new(Some(handler), None));
            }
        }
    }

    // Middleware segments collected from the route table.
    pub fn get_middleware_segments(&self) -> HashSet<&RouteTableKey> {
        // Returns the paths that are used for middleware.

        self.get_routes()
            .iter()
            .fold(HashSet::new(), |mut acc, (key, value)| {
                // We are working on normalized paths, one prefixed with SpecialDirectories. Segment cannot be set on SpecialDirectories.

                // // Try to strip the prefix.
                // let path = key
                //     .get_path()
                //     .strip_prefix(SpecialDirectories::Pages.to_string());

                // Would resolve :database/ => pages/:database/index.html
                // Invalid segment: database/tasks.json => False

                // Should work like
                // :database/tasks/ => database/tasks/slaves.json, etc.
                // :database/ => database/tasks.json, database/users.json, etc.

                // That works on normalized paths, since it does not work and the paths starts with SpecialDirectories
                // as the segment would resolve to directories when no direct mapping to the file exists as segments do not contain files
                // and are treated as directories in normalization.
                if value.get_middleware().is_some() && key.get_path().starts_with(PATH_SEGMENT) {
                    acc.insert(key);
                }

                acc
            })
    }

    /// Inserts a MiddlewareHandler into the route table for the given key,
    ///
    /// Will panic if  MiddlewareHandler already exists for the same path and method or if the route.
    /// already exists for that path with both RouteHandler and MiddlewareHandler.
    ///
    /// For insert_middleware to work it has to match the paths given in the `HashSet<RouteTableKey>` which is used
    /// to match the middleware paths.
    pub fn insert_middleware(&mut self, key: RouteTableKey, handler: MiddlewareHandler) {
        // Insert the route into the table, replacing any existing route with the same key.

        let (method, path) = (key.get_method(), key.get_path());
        // let (handler, middleware) = (handler.clone(), Some(handler.clone()));

        let mut insert_middleware_closure = |key, handler| match self
            .get(&key)
            .map(|v| (v.get_handler().cloned(), v.get_middleware().cloned()))
        {
            // Duplicate MiddlewareHandler, route does not matter.
            Ok((_, Some(_))) => {
                panic!(
                    "Middleware already defined for path: {:?} with method: {:?}",
                    path, method
                );
            }
            // Route exists with RouteHandler but no MiddlewareHandler, we will replace it with the new MiddlewareHandler
            // and previous value for RouteHandler, but cloning the pointer so new reference.
            Ok((Some(route), None)) => {
                // If the route exists with a RouteHandler but no MiddlewareHandler, we replace it with the new MiddlewareHandler.
                // This is useful for routes that should have middleware applied to them.

                // Cloning a route is 8 bytes. We can afford that.
                let route = Some(route.clone());

                self.get_routes_mut()
                    .insert(key, RouteTableValue::new(route, Some(handler)))
            }
            // No route for that key, we are inserting one with MiddlewareHandler defined.
            _ => self
                .get_routes_mut()
                .insert(key, RouteTableValue::new(None, Some(handler))),
        };

        if let None = method {
            for method in HttpRequestMethod::iter() {
                insert_middleware_closure(RouteTableKey::new(path, Some(method)), handler.clone());
            }
        } else {
            insert_middleware_closure(key.clone(), handler);
        }
    }

    /// Searches for a route with given key, it will try to look up the path as is
    /// and if not found, it will try to normalize the path and look it up again. Path is already validated.
    /// Validation takes place in the `HttpRequestHeaders::validate_request_target_path` in `RouteTableKey::new`
    /// and when request from the client in `HttpRequestRequestLine::new`.
    pub fn get(
        &self,
        key: &RouteTableKey,
    ) -> Result<Arc<RouteTableValue>, Box<dyn Error + Send + Sync>> {
        // Get the route handler for the given key, if it exists.
        return self
            .get_routes()
            .get(&key)
            .map(|v| Arc::clone(v))
            .ok_or_else(|| {
                Box::<dyn Error + Send + Sync>::from(format!(
                    "Route not found for path: {:?} with method: {:?}",
                    key.get_path(),
                    key.get_method()
                ))
            });
    }

    /// Statically creates the routes based on the user definitions of the routes with appropriate handlers.
    ///
    /// Automatically collects the routes from the `SpecialDirectories` and inserts them into the route table.
    pub fn create_routes() -> Result<Self, Box<dyn Error + Send + Sync>> {
        // We have the routes cached in the file that is composed in runtime and parsed to some context at startup.
        // We check if the path exists the cached routes or is that a new route that we have defined in the code in that function.

        // 1. We did not found the path => We have to evaluate every path also by instantiating the handler function
        //  -> which is a closure and that would capture it's environment occupying some memory. That would be a O(n) operation to search for route. We can't allow that.
        // 2. We did found the path => ACTUALLY: As I am thinking about that, we either way would have to evaluate each handler function making that design.
        //  -> only way we would not is a match statement that would be a O(1) operation.

        // We will not store the closures in the routes as that would waste memory as we have to evaluate the whole table of routes
        // on startup or when the first request comes in. We would use function pointers, that would be only 8 bits per function on x64 architecture.

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

                routes.insert_handler(key, RouteHandler::new(RouteHandler::static_route_handler))
            });

        // Populates the middleware paths with handlers

        Middleware::create_middleware(&mut routes);

        // ### Database Routes ###

        routes.insert_handler(
            RouteTableKey::new("database/tasks.json", Some(HttpRequestMethod::GET)),
            RouteHandler::new(|ctx: RouteHandlerContext| {
                Box::pin(async move {
                    let RouteHandlerContext {
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

                    return Ok(RouteHandlerResult {
                        headers: response_headers,
                        body,
                    });
                })
            }),
        );

        // Abstracted route handler that does not exists in the file system.
        // Abstracted path is a path that do not resole to file system if normalized.
        routes.insert_handler(
            RouteTableKey::new("/message", Some(HttpRequestMethod::GET)),
            RouteHandler::new(|ctx| {
                Box::pin(async move {
                    // First borrow immutably
                    let database = ctx.get_database()?;
                    let database_config = ctx.get_database_config()?;

                    // Then destructure for owned values.
                    let RouteHandlerContext {
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

                    return Ok(RouteHandlerResult {
                        headers: response_headers,
                        body,
                    });
                })
            }),
        );

        // #####

        println!("{:#?}", routes);

        Ok(routes)
    }

    /// `NOTE`: I am a mistake implementing the RouteResult as an enum that could return standalone the result of the middleware handler.
    /// That is not the case as middleware does not produce the body and if the handler does not exists, but cannot respond with data.
    /// We will keep the functionality, maybe we will utilize it as it is not a big deal to keep it in the code. But keep in mind
    /// That currently the function returns only the `RouteResult::RouteResult` of type `RouteHandlerResult<'ctx>`,
    ///
    /// `NOTE`: Route with defined middleware and undefined handler could only be valid if the middleware is a segment, given that special case
    /// we need to keep the `RouteHandler` as `Option<RouteHandler>` in the `RouteTableValue` struct.
    pub async fn route<'ctx>(
        &self,
        mut ctx: RouteHandlerContext<'ctx>,
        // RouteHandlerResult<'ctx>
    ) -> Result<RouteResult<'ctx>, Box<dyn Error + Send + Sync>> {
        // Check if the path matches any of the middleware segments.

        // Route has to exist for middleware segment to run, as if not, if path is given as invalid there, that would just return an error,
        // but despite that middleware segment could run.
        let route = self.get(ctx.get_key()).map_err(|message| {
            Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                status_code: 404,
                status_text: "Not Found".to_string(),
                message: Some(message.to_string()),
                ..Default::default()
            })
        })?;

        // Router {
        // RouteTable => (RouteHandler, MiddlewareHandler)
        // Middleware => {
        //    segments: {},
        // }
        // }

        // Segments should be resolved in the order of their strength, so the more specific segment would run on the path.
        // :database/ => database/*
        // :database/tasks/ => This segment is stronger, so it should run on the paths containing database/tasks, :database should not run.

        for middleware_key in self.get_middleware_segments() {
            // Check if the path given in the key matches some middleware segment.
            // Consider the strength of the segment, see above.
            if true
            // if ctx
            //     .get_key()
            //     .get_path()
            //     .components()
            //     .any(|c| c.as_os_str() == middleware_key.get_path())
            //     && ctx.get_key().get_method() == middleware_key.get_method()
            {
                // Parse the path to remove the leading `:`.
                let path = middleware_key.parse_middleware_path();

                let key = RouteTableKey::new(path, ctx.get_key().get_method().clone());

                // We don't want to propagate the error if the middleware is not found, just keep searching.
                if let Ok(Some(middleware)) = self.get(&key).map(|v| v.get_middleware().cloned()) {
                    // Give back the context to the route handler.
                    ctx = middleware.callback(ctx).await?.ctx;
                }

                println!(
                    "Running middleware segment {:?} for path: {:?}",
                    middleware_key.get_path(),
                    ctx.get_key().get_path()
                );
            }
        }

        let (handler, middleware) = (route.get_handler(), route.get_middleware());

        match (handler, middleware) {
            // Middleware but no handler, we run the middleware return the ctx.
            // UPDATE: That is not a valid state, as we should always have a handler for the path.
            // (None, Some(middleware)) => {
            //     let result = middleware.callback(ctx).await?;
            //
            //     return Ok(RouteResult::MiddlewareResult(result));
            // }

            // Handle exists, despite the middleware, return the result of the handler.
            (Some(handler), middleware) => {
                // Check if the middleware exists, if it does, we run it, update the ctx.

                if let Some(middleware) = middleware {
                    ctx = middleware.callback(ctx).await?.ctx;
                }

                // If the handler exists, we call it with the context and return the result.

                return Ok(RouteResult::RouteResult(handler.callback(ctx).await?));

                // Run the handler for the path.
            }
            _ => {
                return Err(Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                    status_code: 404,
                    status_text: "Not Found".to_string(),
                    message: Some(format!(
                        "Route not found for path: {:?} with method: {:?}",
                        ctx.get_key().get_path(),
                        ctx.get_key().get_method()
                    )),
                    ..Default::default()
                }))
            }
        };

        // TODO: I think we should redirect to a 404 page or something like that.
        // But we need the functionality for that.
    }
}
