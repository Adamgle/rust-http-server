use std::{
    collections::{HashMap, HashSet},
    error::Error,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use strum::IntoEnumIterator;
use tokio::sync::Mutex;

use crate::{
    config::{database::Database, SpecialDirectories},
    http::{HttpRequestError, HttpRequestHeaders, HttpRequestMethod, HttpResponseHeaders},
    http_request::HttpRequest,
    middleware::{Middleware, MiddlewareHandler, PATH_SEGMENT},
};

// NOTE: Route table does live for the duration of the program, but not the values it is referencing.
// whatever we put in the route table is valid for static, but not the values it is referencing.
// We need to copy that values to put it in the route table because values it is referencing are not
// static and will be wasted from memory after request is done.

// NOTE: Lifetimes are not practically even in this code, as the RouteTable does not have not tied
// the request and response headers to the lifetime of struct, it is independent and those values lives shorter lifetime.

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
                routes.push(format!("{:?} {:?}", key, value));
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
        // Custom debug implementation to show the route handler and middleware handler.
        // f.debug_tuple("RouteTableValue")
        //     .field(&self.get_handler().map(|_| format!("Some(_)")))
        //     .field(&self.get_middleware().map(|_| format!("Some(_)")))
        // .finish()

        // write!(f, "[{}] {})", method_str, path_str)

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

    /// Paths is expected to be relative to the root of the server, so it should not start with `/` or `\` or have a root.
    pub fn new(path: impl AsRef<Path>, method: Option<HttpRequestMethod>) -> Self {
        // Self(Self::create_relative_path(path), method)
        // We would panic if path cannot be normalized, so we can change the static definition of the path
        // as this could be consider a typo in the code.

        // First validate, then normalize.

        // That would not be necessary if validate_request_target_path would operate on `Path` || `PathBuf` || impl AsRef<Path>.
        let path_string = path
            .as_ref()
            .to_str()
            .map(|s| s.to_string())
            .expect("Path must be valid UTF-8");

        if let Err(e) = HttpRequestHeaders::validate_request_target_path(path_string) {
            panic!("Could not validate path: {:?}", e);
        };

        let path = path.as_ref();

        Self(
            HttpRequestHeaders::normalize_path(path).expect(&format!(
                "Could not normalize path: {}, possible typo in the code!",
                path.display()
            )),
            method,
        )
    }

    pub fn get_path(&self) -> &PathBuf {
        // Returns the path of the route table key.
        &self.0
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
    pub fn parse_middleware_path(&self) -> &Path {
        // Parses the middleware path by removing the leading `:` segment if it exists.
        // This is used to normalize the path for middleware handling.

        let path = self.get_path();

        // That is stupid, but I want to use the same piece of code that does the same logic
        // because if we would change the segment recognition logic, we would have to change it in two places.
        if Self::is_path_segment(&path) {
            return path.strip_prefix(PATH_SEGMENT).unwrap();
        }

        return path;
    }

    ///
    pub fn is_path_segment(path: &Path) -> bool {
        // Checks if the path is a segment path, meaning it starts with `:`.
        path.starts_with(PATH_SEGMENT)
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
        write!(f, "[{}] {})", method_str, path_str)
    }
}

/// Context for the route handler that takes a reference `HttpRequest`, a mutable reference to `HttpResponseHeaders, and a
/// reference to `RouteTableKey`.
///
/// NOTE: The lifetimes here are a bit tricky. The `HttpRequest` and `HttpResponseHeaders` are tied to the request lifecycle.
/// `RouteTableKey` even though is 'static in lifetime in the `RouteTable` it is not static in the parameters of the route handler
/// as it is a reference to the key built in the `handle_client` entry point.

#[derive(Debug)]
pub struct RouteHandlerContext<'ctx>(
    &'ctx HttpRequest<'ctx>,
    HttpResponseHeaders<'ctx>,
    &'ctx RouteTableKey,
    Result<Arc<Mutex<Database>>, Box<dyn Error + Send + Sync>>,
    // Config cannot be used there Config itself contains the RouteTable, that would be a circular reference.
    // Maybe we would no have issues with that as Config is in Arc<Mutex<_>>, but we won't do that.
    // If we would access that filed we would have a problem.
);

impl<'ctx> RouteHandlerContext<'ctx> {
    pub fn new(
        request: &'ctx HttpRequest<'ctx>,
        response_headers: HttpResponseHeaders<'ctx>,
        key: &'ctx RouteTableKey,
        database: Result<Arc<Mutex<Database>>, Box<dyn Error + Send + Sync>>,
    ) -> Self {
        Self(request, response_headers, key, database)
    }

    pub fn get_request(&self) -> &HttpRequest<'ctx> {
        // Returns the request of the route handler context.
        self.0
    }

    pub fn get_response_headers(&mut self) -> &mut HttpResponseHeaders<'ctx> {
        // Returns the response headers of the route handler context.
        &mut self.1
    }

    // Returns the key of the route handler context.
    pub fn get_key(&self) -> &RouteTableKey {
        &self.2
    }

    pub fn get_database(&self) -> &Result<Arc<Mutex<Database>>, Box<dyn Error + Send + Sync>> {
        // Returns the database of the route handler context.
        &self.3
    }
}

// A closure returns a Future that resolves to a function pointer that resolves to Result of a web request, request body.

/// Take an owned version of headers that was previously moved from `handle_client` and the result of the
/// request consisting of the body.
///
/// Applies changes to headers as defined in the handler for a given path.
pub struct RouteHandlerResult<'b> {
    pub headers: HttpResponseHeaders<'b>,
    pub body: Result<String, Box<dyn Error + Send + Sync>>,
}

/// Result of the function pointer for the route handler.
// type RouteHandlerFunctionPointerResult = Result<String, Box<dyn Error + Send + Sync>>;

// Function pointer for the route handler.
// type RouteHandlerFunctionPointer =
//     for<'ctx> fn(RouteHandlerContext<'ctx>) -> RouteHandlerFunctionPointerResult;

// A callback lives for 'static
// UPDATE: Callback cannot live for 'static as the Context gets moved in to a closure
// and then lifetime it utilizes would become invariant. That means a lifetime of context
// would have to be the same as the lifetime of 'static, but Context that lifetime "for all 'ctx".
// We need to pass generic lifetime from the RouteHandlerClosure to use the same exact lifetime as there declared.
type RouteHandlerFuture<'ctx> =
    Pin<Box<dyn Future<Output = RouteHandlerResult<'ctx>> + Send + 'ctx>>;

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
    pub fn new(handler: fn(RouteHandlerContext) -> RouteHandlerResult) -> Self {
        let c: RouteHandlerClosure = Arc::new(move |ctx| {
            // Wraps the function pointer in an Arc to allow shared ownership.
            Box::pin(async move { handler(ctx) })
        });

        Self(c)
    }

    // fn wrap_handler(handler: RouteHandlerFunctionPointer) -> RouteHandlerClosure {
    //     Arc::new(move |ctx| Box::pin(async move { handler(ctx) }))
    // }

    /// NOTE: The function that is called inside the callback is not async itself, but when called with
    /// callback it would be. This is due to how RouteHandler is initialized, that you can pass a function pointer
    /// that would coerced to an async function.
    ///
    /// Calls the function pointer with ctx.
    pub async fn callback<'ctx>(&self, ctx: RouteHandlerContext<'ctx>) -> RouteHandlerResult<'ctx> {
        (self.0)(ctx).await
    }

    /// A static route handler that reads the requested resource from the `/public` directory.
    pub fn static_route_handler<'ctx>(ctx: RouteHandlerContext<'ctx>) -> RouteHandlerResult<'ctx> {
        let RouteHandlerContext(req, mut res_headers, key, _) = ctx;

        let body = req.read_requested_resource(&mut res_headers, key.get_path());

        return RouteHandlerResult {
            headers: res_headers,
            body,
        };
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

        let mut insert_handler_closure = |key: RouteTableKey, handler: RouteHandler| {
            match self
                .get(&key)
                .map(|v| (v.get_handler().cloned(), v.get_middleware().cloned()))
            {
                Some((Some(_), Some(_))) => {
                    // Route exists with both RouteHandler and MiddlewareHandler — panic duplicate
                    panic!(
                        "Route already defined for path: {:?} with method: {:?}",
                        path, method
                    );
                }
                Some((Some(_), None)) => {
                    // Duplicate RouteHandler exists — panic
                    panic!(
                        "RouteHandler already defined for path: {:?} with method: {:?}",
                        path, method
                    );
                }
                // Middleware exists but no RouteHandler — insert new RouteHandler while preserving middleware
                Some((None, Some(middleware))) => {
                    let middleware = middleware.clone();

                    self.get_routes_mut()
                        .insert(key, RouteTableValue::new(Some(handler), Some(middleware)));
                }
                // No route exists or no handlers — insert new RouteHandler
                _ => {
                    self.get_routes_mut()
                        .insert(key, RouteTableValue::new(Some(handler), None));
                }
            }
        };

        if method.is_none() {
            for method in HttpRequestMethod::iter() {
                insert_handler_closure(
                    RouteTableKey::new(path.clone(), Some(method)),
                    handler.clone(),
                );
            }
        } else {
            insert_handler_closure(key.clone(), handler);
        }
    }

    // Gets the paths that are used for middleware.
    pub fn get_middleware_segments(&self) -> HashSet<&RouteTableKey> {
        // Returns the paths that are used for middleware.

        self.get_routes()
            .iter()
            .fold(HashSet::new(), |mut acc, (key, value)| {
                // :database/tasks.json =>
                // database/tasks.json +>

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

        // If the path has a segment that starts with `:`, it is a middleware path.
        // 1. Check if it is not a file path, if it is, we panic.
        // 2. Segment paths should resolve to the normal paths, we need some parser for that for MiddlewarePath.
        //  -> Of course currently that just mean we need to strip the ":" from the path, but in the future we might want to support more complex paths.
        // 3. After the segment path resolves direct => pages/direct/index.html, the path should get normalized
        //  -> We would have to choose use the one declared directly on the path, or the one that is parsed to the path from the segment.
        // 4. If after parsing the path we already have the key for that path, we panic, as that is a duplicate path.
        //  -> Meaning `:database/routes` => `database/routes` and "database/routes", if both have middleware defined we would have to panic
        //  -> As one would cover the other, of course we could just invoke both, but that is invalid, there cannot be 2 middleware handlers for the same path.

        let (method, path) = (key.get_method(), key.get_path());
        // let (handler, middleware) = (handler.clone(), Some(handler.clone()));

        let mut insert_middleware_closure = |key, handler| match self
            .get(&key)
            .map(|v| (v.get_handler().cloned(), v.get_middleware().cloned()))
        {
            Some((Some(_), Some(_))) => {
                // If the route already exists with both RouteHandler and MiddlewareHandler, we panic.
                // This is a case of duplicated middleware for the same path and method.
                panic!(
                    "Route already defined for path: {:?} with method: {:?}",
                    path, method
                );
            }
            // Duplicate MiddlewareHandler
            Some((_, Some(_))) => {
                panic!(
                    "Middleware already defined for path: {:?} with method: {:?}",
                    path, method
                );
            }
            // Route exists with RouteHandler but no MiddlewareHandler, we will replace it with the new MiddlewareHandler
            // and previous value for RouteHandler, but cloning the pointer so new reference.
            Some((Some(route), None)) => {
                // If the route exists with a RouteHandler but no MiddlewareHandler, we replace it with the new MiddlewareHandler.
                // This is useful for routes that should have middleware applied to them.
                let route = Some(route.clone());

                self.get_routes_mut().insert(
                    key,
                    // Cloning a route is 8 bytes. We can afford that.
                    RouteTableValue::new(route, Some(handler)),
                )
            }
            // No existing route for that key, or route exists with no RouterHandler and MiddlewareHandler.
            _ => self
                .get_routes_mut()
                .insert(key, RouteTableValue::new(None, Some(handler))),
        };

        if let None = method {
            for method in HttpRequestMethod::iter() {
                insert_middleware_closure(
                    RouteTableKey::new(path.clone(), Some(method)),
                    handler.clone(),
                );
            }
        } else {
            insert_middleware_closure(key.clone(), handler);
        }
    }

    pub fn get(&self, key: &RouteTableKey) -> Option<Arc<RouteTableValue>> {
        // Get the route handler for the given key, if it exists.
        self.get_routes().get(key).map(|v| Arc::clone(v))
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

                routes.insert_handler(key, RouteHandler::new(RouteHandler::static_route_handler));
            });

        // Populates the middleware paths with handlers

        Middleware::create_middleware(&mut routes);

        // ### Database Routes ###

        routes.insert_handler(
            RouteTableKey::new(
                Path::new("database/tasks.json"),
                Some(HttpRequestMethod::GET),
            ),
            RouteHandler::new(|ctx: RouteHandlerContext| {
                // Here we would handle the POST request to the tasks.json file.
                // This is just a placeholder for the actual implementation.

                // NOTE: Refactor handlers to return the Result
                // let database = ctx.get_database()?;

                println!("Creating a new task with context: {:?}", ctx);
                // database always exists in the database/ segments.

                return RouteHandlerResult {
                    headers: ctx.1,
                    body: Ok(String::new()),
                };
            }),
        );

        println!("Routes: {:#?}", routes);

        Ok(routes)
    }

    // pub async fn route(&self, ctx: RouteHandlerContext<'_>) -> RouteHandlerFunctionPointerResult {
    //     // 1) Pull the &mut headers out temporarily:
    //     let RouteHandlerContext(req, res_headers, key, db) = ctx;

    //     // do any pre-handler sync mutations here:
    //     res_headers.add("X-Powered-By".into(), "Rust".into());

    //     // rebuild a fresh ctx, so the &mut borrow ends:
    //     let mut ctx = RouteHandlerContext::new(req, res_headers, key, db);

    //     for middleware_key in self.get_middleware_segments() {
    //         if ctx
    //             .get_key()
    //             .get_path()
    //             .starts_with(middleware_key.get_path())
    //             && ctx.get_key().get_method() == middleware_key.get_method()
    //         {
    //             // Parse the path to remove the leading `:`.
    //             let path = middleware_key.parse_middleware_path();

    //             let key = RouteTableKey::new(path, ctx.get_key().get_method().clone());

    //             if let Some(Some(middleware)) = self
    //                 .get(&key)
    //                 .map(|v| v.get_middleware().map(|v| v.clone()))
    //             {
    //                 // Give back the context to the route handler.

    //                 ctx = middleware.callback(ctx).await?;
    //             }

    //             println!(
    //                 "Running middleware for path: {:?}",
    //                 ctx.get_key().get_path()
    //             );
    //         }
    //     }

    //     if let Some(route) = self.get(ctx.get_key()) {
    //         if let Some(mw) = route.get_middleware().map(|v| v.clone()) {
    //             ctx = mw.callback(ctx).await?;
    //         }
    //         if let Some(h) = route.get_handler().map(|v| v.clone()) {
    //             return h.callback(ctx).await;
    //         }
    //     }

    //     Err(Box::new(HttpRequestError {
    //         status_code: 404,
    //         status_text: "Not Found".to_string(),
    //         message: Some(format!(
    //             "Route not found for path: {} and method: {:?}",
    //             ctx.get_key().get_path().display(),
    //             ctx.get_key().get_method() // ctx.get_key().get_method()
    //                                        // key.get_path().display(),
    //                                        // key.get_method() // ctx.get_key().get_method()
    //         )),
    //         ..Default::default()
    //     }))
    // }

    pub async fn route<'ctx>(
        &self,
        mut ctx: RouteHandlerContext<'ctx>,
    ) -> Result<RouteHandlerResult<'ctx>, Box<dyn Error + Send + Sync>> {
        // Look up the handler for the route key in the route table.

        // Check if the route path matches any of the middleware paths, but testing if the path
        // starts with the path of the middleware.

        // Running middleware for segments, paths prefixed with ":" that run on each path that starts with that segment.
        // That is f'ed up because we check if there is a segment after the normalization and we get nothing, as after normalization
        // it would be prefixed with "pages/" and suffixed with "index.html"
        println!("Segments: {:?}", self.get_middleware_segments());

        for middleware_key in self.get_middleware_segments() {
            if ctx
                .get_key()
                .get_path()
                .starts_with(middleware_key.get_path())
                && ctx.get_key().get_method() == middleware_key.get_method()
            {
                // Parse the path to remove the leading `:`.
                let path = middleware_key.parse_middleware_path();

                let key = RouteTableKey::new(path, ctx.get_key().get_method().clone());

                if let Some(middleware) = self.get(&key).and_then(|v| v.get_middleware().cloned()) {
                    // Give back the context to the route handler.
                    ctx = middleware.callback(ctx).await.ctx?;
                    // let mut result = middleware.callback(ctx).await?;
                    // let mut ctx = result.ctx;
                    // ctx.1 = result.headers;
                    // Pass the ctx to the route handler.
                }

                println!(
                    "Running middleware for path: {:?}",
                    ctx.get_key().get_path()
                );
            }
        }

        if let Some(route) = self.get(ctx.get_key()) {
            // Call the handler with the context and return the result.

            let (handler, middleware) = (route.get_handler(), route.get_middleware());

            // That is useless as the before code would also match.
            if let Some(middleware) = middleware {
                // If middleware fails, we return an error, without evaluating the path it is attached to, if any path given.

                // This runs the middleware on the actual path, not the segment of that path.
                ctx = middleware.callback(ctx).await.ctx?;
            }

            if let Some(handler) = handler {
                // If the handler exists, we call it with the context and return the result.

                // Wrapped in a Result just for middleware return type compatibility.
                return Ok(handler.callback(ctx).await);
            }
        }

        // If no route is found, return an error.

        // TODO: I think we should redirect to a 404 page or something like that.
        // But we need the functionality for that.

        Err(Box::new(HttpRequestError {
            status_code: 404,
            status_text: "Not Found".to_string(),
            message: Some(format!(
                "Route not found for path: {} and method: {:?}",
                ctx.get_key().get_path().display(),
                ctx.get_key().get_method() // ctx.get_key().get_method()
                                           // key.get_path().display(),
                                           // key.get_method() // ctx.get_key().get_method()
            )),
            ..Default::default()
        }))
    }
}
