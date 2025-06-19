use std::{
    collections::{HashMap, HashSet},
    error::Error,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use strum::IntoEnumIterator;
use tokio::sync::MutexGuard;

use crate::{
    config::{Config, SpecialDirectories},
    http::{HttpRequestError, HttpRequestHeaders, HttpRequestMethod, HttpResponseHeaders},
    http_request::HttpRequest,
    middleware::{Middleware, MiddlewareClosure, MiddlewareFunctionPointer, PATH_SEGMENT},
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
        // Custom debug implementation to show the keys and number of routes.
        f.debug_struct("RouteTable")
            .field(
                "routes",
                &self
                    .0
                    .iter()
                    // NOTE: Showing function pointers as their memory addresses is useless, but it is FUN!
                    // .map(|(k, &v)| (k, format!("function::<{:p}>", v as *const ())))
                    .map(|(k, v)| {
                        let (handler, middleware) = (v.get_handler(), v.get_middleware());

                        // (
                        //     k,
                        //     format!(
                        //         "Handler at: {:?}, Middleware at: {:?}",
                        //         handler.as_ref().map(|h| h.0 as *const ()),
                        //         middleware.as_ref().map(|m| m.0 as *const ())
                        //     ),
                        // )
                    })
                    .collect::<Vec<_>>(),
            )
            .finish()?;

        Ok(())
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

/// Routing table lives for the whole lifetime of the server, since path is a `static` lifetime.
///
/// Method is optional to support middleware paths that can be run with any method.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct RouteTableKey(pub PathBuf, pub Option<HttpRequestMethod>);

impl RouteTableKey {
    /// Creates a new route table key with the given path and method.

    /// Paths is expected to be relative to the root of the server, so it should not start with `/` or `\` or have a root.
    pub fn new(path: impl AsRef<Path>, method: Option<HttpRequestMethod>) -> Self {
        // Self(Self::create_relative_path(path), method)
        // We would panic if path cannot be normalized, so we can change the static definition of the path
        // as this could be consider a typo in the code.

        Self(
            HttpRequestHeaders::normalize_path(path)
                .expect("Could not normalize the path, possible typo in the path"),
            method,
        )
    }

    pub fn get_path(&self) -> &PathBuf {
        // Returns the path of the route table key.
        &self.0
    }
    /// Check if the path is absolute, panics if not, as that is a typo in the code.
    ///
    /// Since we are making the paths static we need to make sure they are relative to the root because, first, they are resolved this way
    /// and second, we don't want to make any mistakes with typos so we make this function to thrown and error or recover simple mistakes.
    /// Although throwing an error would be more stable, as they are just typos.
    // pub fn create_relative_path(path: PathBuf) -> PathBuf {
    //     if path.starts_with("/") || path.starts_with("\\") || path.has_root() || path.is_absolute()
    //     {
    //         // If the path is absolute or has a root, we return an error, let the developer to fix the typo!
    //         panic!(
    //             "The path {:?} is absolute or has a root, use relative paths only!",
    //             path
    //         );
    //     } else {
    //         // If the path is not absolute, we return it as is.
    //         path
    //     }
    // }

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

/// Context for the route handler that takes a reference `HttpRequest`, a mutable reference to `HttpResponseHeaders, and a
/// reference to `RouteTableKey`.
///
/// NOTE: The lifetimes here are a bit tricky. The `HttpRequest` and `HttpResponseHeaders` are tied to the request lifecycle.
/// `RouteTableKey` even though is 'static in lifetime in the `RouteTable` it is not static in the parameters of the route handler
/// as it is a reference to the key built in the `handle_client` entry point.

#[derive(Debug)]
// pub struct RouteHandlerContext<'a>(
//     &'a HttpRequest<'a>,
//     &'b mut HttpResponseHeaders<'a>,
//     &'a RouteTableKey,
//     // NOTE: Not sure about the lifetime down there.
//     &'a MutexGuard<'a, Config>,
//     // Option<&'a DatabaseConfigEntry>,
//     // &'a Option<Arc<Mutex<Database>>>,
// );

pub struct RouteHandlerContext<'a>(
    &'a HttpRequest<'a>,
    &'a mut HttpResponseHeaders<'a>,
    &'a RouteTableKey,
    // NOTE: Not sure about the lifetime down there.
    &'a MutexGuard<'a, Config>,
    // Option<&'a DatabaseConfigEntry>,
    // &'a Option<Arc<Mutex<Database>>>,
);

impl<'a> RouteHandlerContext<'a> {
    pub fn new(
        request: &'a HttpRequest<'a>,
        response_headers: &'a mut HttpResponseHeaders<'a>,
        key: &'a RouteTableKey,
        config: &'a MutexGuard<'a, Config>,
    ) -> Self {
        Self(request, response_headers, key, config)
    }

    pub fn get_request(&self) -> &HttpRequest<'a> {
        // Returns the request of the route handler context.
        self.0
    }

    pub fn get_response_headers(&mut self) -> &mut HttpResponseHeaders<'a> {
        // Returns the response headers of the route handler context.
        self.1
    }

    // Returns the key of the route handler context.
    pub fn get_key(&self) -> &RouteTableKey {
        &self.2
    }

    pub fn get_config(&self) -> &MutexGuard<'a, Config> {
        // Returns the config of the route handler context.
        self.3
    }
}

/// Result of the function pointer for the route handler.
type RouteHandlerFunctionPointerResult = Result<String, Box<dyn Error + Send + Sync>>;

// Function pointer for the route handler.
type RouteHandlerFunctionPointer =
    for<'a> fn(RouteHandlerContext<'a>) -> RouteHandlerFunctionPointerResult;

// A boxed future that resolves to the Result of the route handler function pointer.
type RouteHandlerClosureResult<'a> =
    Pin<Box<dyn Future<Output = RouteHandlerFunctionPointerResult> + Send + 'a>>;

// TODO: The struct of RouteHandlerValue is already behind Arc, check how to avoid one of the Arc's.
// A closure of the route handler
// We could not make it work with the function pointer directly as we want to use async/await syntax,
// Maybe if we closure is behind the Arc it would not take much memory.
type RouteHandlerClosure =
    Arc<dyn for<'a> Fn(RouteHandlerContext<'a>) -> RouteHandlerClosureResult<'a> + Send + Sync>;

// Arc::new(|ctx| )

/// A function pointer that takes executed to handle specific route.
///
/// The idea is that the `RouteHandler` being a function pointer stored in the `Arc` is valid for the duration of the program,
/// and can be referenced via multiple async tasks. Only the parameters `RouteHandlerContext` passed to the handler
/// are changing with each request and we make sure to not store that references in the routing table.
//
// NOTE: We wrap the function pointer in the `Arc` inside the `RouteTable` as we want to allow multiple tasks to access
// the same `RouteHandler`, not only the function pointer if we would want to lay some abstraction onto that handler.
#[derive(Clone)]
pub struct RouteHandler(RouteHandlerClosure);

impl std::fmt::Debug for RouteHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Custom debug implementation to show the function pointer address.
        f.debug_struct("RouteHandler")
            // .field("function_pointer", &format!("{:p}", self.0 as *const ()))
            .finish()
    }
}

impl RouteHandler {
    pub fn new<'a>(handler: RouteHandlerFunctionPointer) -> Self {
        // RouteHandler::new(Arc::new(|ctx| RouteHandler::static_route_handler(ctx)))
        Self(Self::wrap_handler(handler))
    }

    fn wrap_handler<'a>(handler: RouteHandlerFunctionPointer) -> RouteHandlerClosure {
        Arc::new(move |ctx| Box::pin(async move { handler(ctx) }))
    }

    pub async fn callback<'a>(
        &self,
        ctx: RouteHandlerContext<'a>,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        // Call the function pointer with the request, response headers, and key.
        // let a = self.0.as_ref();

        (self.0)(ctx).await
    }

    /// A static route handler that reads the requested resource from the `/public` directory.
    pub fn static_route_handler<'a>(
        ctx: RouteHandlerContext<'a>,
    ) -> RouteHandlerFunctionPointerResult {
        let RouteHandlerContext(req, res, key, _) = ctx;

        Ok(req.read_requested_resource(res, key.get_path())?)
    }
}

#[derive(Clone)]
pub struct MiddlewareHandler(MiddlewareClosure);

impl std::fmt::Debug for MiddlewareHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Custom debug implementation to show the function pointer address.
        f.debug_struct("MiddlewareHandler")
            // .field("function_pointer", &format!("{:p}", self.0 as *const ()))
            .finish()
    }
}

impl MiddlewareHandler {
    pub fn new(handler: MiddlewareFunctionPointer) -> Self {
        Self(Self::wrap_handler(handler))
    }

    pub fn wrap_handler<'a>(handler: MiddlewareFunctionPointer) -> MiddlewareClosure {
        // Wraps the function pointer in an Arc to allow shared ownership.
        Arc::new(move |ctx| Box::pin(async move { handler(ctx) }))
    }

    pub async fn callback<'a>(
        &self,
        ctx: RouteHandlerContext<'a>,
    ) -> Result<RouteHandlerContext<'a>, Box<dyn Error + Send + Sync>> {
        // Call the middleware function pointer with the request, response headers, and key.

        (self.0)(ctx).await
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
                .map(|v| (v.get_handler(), v.get_middleware()))
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

        let mut insert_middleware_closure = |key, handler| match self
            .get(&key)
            .map(|v| (v.get_handler(), v.get_middleware()))
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

    pub fn get(&self, key: &RouteTableKey) -> Option<&Arc<RouteTableValue>> {
        // Get the route handler for the given key, if it exists.
        self.get_routes().get(key)
    }

    /// Statically creates the routes based on the user definitions of the routes with appropriate handlers.
    ///
    /// Automatically collects the routes from the `SpecialDirectories` and inserts them into the route table.
    pub fn create_routes() -> Result<RouteTable, Box<dyn Error + Send + Sync>> {
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
            .for_each(|(path, method)| {
                // This callback would be used to handle the request for the static route.
                // The parameters should live for the duration of the request but the callback function
                // should live for 'static

                routes.insert_handler(
                    RouteTableKey::new(path, Some(method)),
                    RouteHandler::new(RouteHandler::static_route_handler),
                );
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
                println!("Creating a new task...");
                // database always exists in the database/ segments.
                Ok(String::from("Ok"))
            }),
        );

        // routes.insert_middleware(
        //     RouteTableKey::new(PathBuf::from("database/"), None),
        //     MiddlewareHandler::new(|ctx| {
        //         // Here we would handle the middleware for the database routes.
        //         // This is just a placeholder for the actual implementation.
        //         println!(
        //             "Running middleware for database path: {:?}",
        //             ctx.get_key().get_path()
        //         );
        //         Ok(ctx)
        //     }),
        // );

        // // NOTE: We should support Any method to run the route.
        // routes.insert(
        //     RouteTableKey::new(PathBuf::from("database/"), None),
        //     RouteTableValue::new(
        //         None,
        //         Some(MiddlewareHandler::new(|ctx| todo!())), // No middleware for this route
        //     ),
        // );

        // I am thinking how can I repeat some logic on specific sub-routes, meaning
        // if I have many routes regarding the database, it would be wise to check for
        // the existence of the config for the database only once. We would need middleware for that.
        // Something that takes the request and response_headers and checks or even mutates the headers
        // before passing it to the handler. This way we could write some piece of code only once.

        // routes.insert(
        //     RouteTableKey::new(
        //         PathBuf::from("database/tasks.json"),
        //         HttpRequestMethod::POST,
        //     ),
        //     RouteHandler::new(|ctx: RouteHandlerContext| {
        //         // Here we would handle the POST request to the tasks.json file.
        //         // This is just a placeholder for the actual implementation.
        //         println!("Creating a new task...");

        //         Ok(String::from("Ok"))
        //     }),
        // );

        println!(
            "All routes: {:#?}",
            routes
                .get_routes()
                .iter()
                .map(|(key, _)| key.get_path())
                .collect::<Vec<_>>()
        );

        fn estimate_route_table_size(route_table: &RouteTable) -> usize {
            let mut total = 0;

            // Size of RouteTable struct itself (HashMap on stack)
            total += size_of_val(route_table);

            // Heap allocated buckets in the HashMap
            let bucket_count = route_table.0.capacity();
            let bucket_size = size_of::<(RouteTableKey, Arc<RouteTableValue>)>();
            total += bucket_count * bucket_size;

            for (key, arc_value) in route_table.0.iter() {
                // Size of the key struct itself (PathBuf + Option<HttpRequestMethod>)
                total += size_of_val(key);

                // Heap inside PathBuf: the allocated string buffer
                total += key.0.capacity();

                // Size of the Arc pointer on stack
                total += size_of_val(arc_value);

                // Size of the RouteTableValue struct inside the Arc heap allocation
                total += size_of_val(arc_value.as_ref());

                // Estimate size of RouteHandler closure environment (if present)
                if let Some(handler) = arc_value.get_handler() {
                    // Arc + guessed closure env size (~64 bytes)
                    total += size_of_val(handler);
                }

                // Estimate size of MiddlewareHandler closure environment (if present)
                if let Some(middleware) = arc_value.get_middleware() {
                    total += size_of_val(middleware);
                }
            }

            total
        }

        println!(
            "Estimated size of RouteTable: {} bytes",
            estimate_route_table_size(&routes)
        );

        Ok(routes)
    }

    /// Routes the request to the appropriate handler based on the key, if it exists.
    ///
    /// Returns the body of the response as a String if the route is found.
    pub async fn route<'a>(
        &self,
        mut ctx: RouteHandlerContext<'a>,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        // Look up the handler for the route key in the route table.

        // println!(
        //     "Routing request for path: {} and method: {:?}",
        //     ctx.get_key().get_path().display(),
        //     ctx.get_key().get_method()
        // );

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

                if let Some(middleware) = self.get(&key).and_then(|v| v.get_middleware()) {
                    // Give back the context to the route handler.
                    ctx = middleware.callback(ctx).await?;
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
                ctx = middleware.callback(ctx).await?;
            }

            if let Some(handler) = handler {
                return handler.callback(ctx).await;
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
