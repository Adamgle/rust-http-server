use std::{collections::HashMap, error::Error, path::PathBuf, sync::Arc};

use crate::{
    config::SpecialDirectories,
    http::{HttpRequestError, HttpRequestMethod, HttpResponseHeaders},
    http_request::HttpRequest,
};

// NOTE: Route table does live for the duration of the program, but not the values it is referencing.
// whatever we put in the route table is valid for static, but not the values it is referencing.
// We need to copy that values to put it in the route table because values it is referencing are not
// static and will be wasted from memory after request is done.

// NOTE: Lifetimes are not practically even in this code, as the RouteTable does not have not tied
// the request and response headers to the lifetime of struct, it is independent and those values lives shorter lifetime.

pub struct RouteTable(HashMap<RouteTableKey, Arc<RouteHandler>>);

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
                    .map(|(k, v)| (k, format!("function::<{:p}>", Arc::as_ptr(v))))
                    .collect::<Vec<_>>(),
            )
            .finish()?;

        Ok(())
    }
}

/// Routing table lives for the whole lifetime of the server, since path is a `static` lifetime.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct RouteTableKey(PathBuf, HttpRequestMethod);

impl RouteTableKey {
    /// Creates a new route table key with the given path and method.

    /// Paths is expected to be relative to the root of the server, so it should not start with `/` or `\` or have a root.
    pub fn new(path: PathBuf, method: HttpRequestMethod) -> Self {
        Self(Self::create_relative_path(path), method)
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
    pub fn create_relative_path(path: PathBuf) -> PathBuf {
        if path.starts_with("/") || path.starts_with("\\") || path.has_root() || path.is_absolute()
        {
            // If the path is absolute or has a root, we return an error, let the developer to fix the typo!
            panic!(
                "The path {:?} is absolute or has a root, use relative paths only!",
                path
            );
        } else {
            // If the path is not absolute, we return it as is.
            path
        }
    }

    pub fn get_method(&self) -> &HttpRequestMethod {
        // Returns the method of the route table key.
        &self.1
    }
}

/// Context for the route handler that takes a reference `HttpRequest`, a mutable reference to `HttpResponseHeaders, and a
/// reference to `RouteTableKey`.
///
/// NOTE: The lifetimes here are a bit tricky. The `HttpRequest` and `HttpResponseHeaders` are tied to the request lifecycle.
/// `RouteTableKey` even though is 'static in lifetime in the `RouteTable` it is not static in the parameters of the route handler
/// as it is a reference to the key built in the `handle_client` entry point.

#[derive(Debug)]
pub struct RouteHandlerContext<'a, 'b>(
    &'a HttpRequest<'a>,
    &'b mut HttpResponseHeaders<'a>,
    &'a RouteTableKey,
);

impl<'a, 'b> RouteHandlerContext<'a, 'b> {
    pub fn new(
        request: &'a HttpRequest<'a>,
        response_headers: &'b mut HttpResponseHeaders<'a>,
        key: &'a RouteTableKey,
    ) -> Self {
        Self(request, response_headers, key)
    }

    pub fn get_key(&self) -> &RouteTableKey {
        // Returns the key of the route handler context.
        &self.2
    }
}

type RouteHandlerFunctionPointer =
    for<'a, 'b> fn(RouteHandlerContext<'a, 'b>) -> Result<String, Box<dyn Error + Send + Sync>>;

type MiddleHandlerFunctionPointer =
    for<'a, 'b> fn(
        RouteHandlerContext<'a, 'b>,
    ) -> Result<RouteHandlerContext<'a, 'b>, Box<dyn Error + Send + Sync>>;

/// A function pointer that takes executed to handle specific route.
///
/// The idea is that the `RouteHandler` being a function pointer stored in the `Arc` is valid for the duration of the program,
/// and can be referenced via multiple async tasks. Only the parameters `RouteHandlerContext` passed to the handler
/// are changing with each request and we make sure to not store that references in the routing table.
//
// NOTE: We wrap the function pointer in the `Arc` inside the `RouteTable` as we want to allow multiple tasks to access
// the same `RouteHandler`, not only the function pointer if we would want to lay some abstraction onto that handler.
pub struct RouteHandler(RouteHandlerFunctionPointer);

impl RouteHandler {
    pub fn new(handler: RouteHandlerFunctionPointer) -> Self {
        Self(handler)
    }

    pub fn callback<'a, 'b>(
        &self,
        ctx: RouteHandlerContext<'a, 'b>,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        // Call the function pointer with the request, response headers, and key.
        (self.0)(ctx)
    }

    /// A static route handler that reads the requested resource from the `/public` directory.
    pub fn static_route_handler<'a, 'b>(
        ctx: RouteHandlerContext<'a, 'b>,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let RouteHandlerContext(req, res, key) = ctx;

        Ok(req.read_requested_resource(res, key.get_path())?)
    }
}

impl RouteTable {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Inserts in to nested HashMap a route with the given key and handler.
    ///
    /// Informing if the route was replaced or not to make debugging easier if we would do the same route name twice.
    pub fn insert(&mut self, key: RouteTableKey, handler: RouteHandler) {
        // Insert the route into the table, replacing any existing route with the same key.
        let Self(routes) = self;

        let path = key.0.clone();

        if let Some(_) = routes.insert(key, Arc::new(handler)) {
            // If there was an existing route, we can log or handle it if needed.
            eprintln!("Replaced existing route for key: {:?}", path);
        }
    }

    pub fn get(&self, key: &RouteTableKey) -> Option<&Arc<RouteHandler>> {
        // Get the route handler for the given key, if it exists.
        self.0.get(key)
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

        // let RouteTable(mut routes) = RouteTable::new();
        let mut routes = RouteTable::new();
        // Every path in the SpecialDirectories can be routed without authentication using GET method.

        // NOTE: I don't like that I have to insert each function pointer manually here.

        SpecialDirectories::collect()
            .inspect_err(|e: &Box<dyn Error + Send + Sync>| {
                eprintln!("Failed to collect static routes: {}", e);
            })?
            .into_iter()
            .for_each(|(path, method)| {
                // This callback would be used to handle the request for the static route.
                // The parameters should live for the duration of the request but the callback function
                // should live for 'static

                routes.insert(
                    RouteTableKey::new(path, method),
                    RouteHandler::new(RouteHandler::static_route_handler),
                );
            });

        // ### Database Routes ###

        // I am thinking how can I repeat some logic on specific sub-routes, meaning
        // if I have many routes regarding the database, it would be wise to check for
        // the existence of the config for the database only once. We would need middleware for that.
        // Something that takes the request and response_headers and checks or even mutates the headers
        // before passing it to the handler. This way we could write some piece of code only once.

        routes.insert(
            RouteTableKey::new(
                PathBuf::from("database/tasks.json"),
                HttpRequestMethod::POST,
            ),
            RouteHandler::new(|ctx: RouteHandlerContext| {
                // Here we would handle the POST request to the tasks.json file.
                // This is just a placeholder for the actual implementation.
                println!("Creating a new task...");

                Ok(String::from("Ok"))
            }),
        );

        println!(
            "All routes: {:#?}",
            routes.0.keys().map(|e| e.get_path()).collect::<Vec<_>>()
        );

        fn estimate_routes_size(table: &RouteTable) -> usize {
            let mut size = std::mem::size_of_val(table); // Shallow RouteTable wrapper

            for (key, handler) in &table.0 {
                // Size of the key (RouteTableKey)
                size += std::mem::size_of_val(key); // RouteTableKey struct (PathBuf + enum)
                size += key.get_path().as_os_str().len(); // PathBuf heap string length
                size += std::mem::size_of_val(key.get_method()); // Enum: HttpRequestMethod

                // Size of Arc<RouteHandler>
                size += std::mem::size_of_val(handler);
                // Arc points to RouteHandler containing a function pointer: fixed size
                size += std::mem::size_of::<RouteHandler>(); // Just the function pointer inside
            }

            size
        }

        println!(
            "Estimated size of RouteTable: {} bytes",
            estimate_routes_size(&routes)
        );

        Ok(routes)
    }

    /// Routes the request to the appropriate handler based on the key, if it exists.
    ///
    /// Returns the body of the response as a String if the route is found.
    pub fn route<'a, 'b>(
        &self,
        ctx: RouteHandlerContext<'a, 'b>,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        // Look up the handler for the route key in the route table.

        if let Some(handler) = self.get(ctx.get_key()) {
            // Call the handler with the context and return the result.

            handler.callback(ctx)
        } else {
            // If no route is found, return an error.

            // TODO: I think we should redirect to a 404 page or something like that.
            // But we need the functionality for that.

            Err(Box::new(HttpRequestError {
                status_code: 404,
                status_text: "Not Found".to_string(),
                message: Some(format!(
                    "Route not found for path: {} and method: {}",
                    ctx.get_key().get_path().display(),
                    ctx.get_key().get_method() // ctx.get_key().get_method()
                                               // key.get_path().display(),
                                               // key.get_method() // ctx.get_key().get_method()
                )),
                ..Default::default()
            }))
        }
    }
}
