use std::{
    collections::{HashMap, HashSet},
    error::Error,
    os::windows::io::InvalidHandleError,
    path::{Path, PathBuf},
};

use crate::{
    http::HttpRequestError,
    router::{
        routes::Routes, RouteContext, RouteEntry, RouteHandler, RouteHandlerFuture,
        RouteHandlerResult, RouteResult, RouteTable, RouteTableKey,
    },
};

use crate::http::HttpHeaders;

pub const PATH_SEGMENT: &str = ":";

/// Middleware run before the actual request handler, and return the context that is passed later to the handler.
///
/// It works on the paths or segments of the path that are prefixed with `:` character.
///
/// for example, `:database/` would run for any path that starts with `database/`, like `database/users` or `database/transactions`.
#[derive(Debug)]
pub struct Middleware {
    routes: RouteTable,
    /// `NOTE`: Route entry should be of RouteEntry::Middleware variant.
    ///
    /// It provides a mapping of the route key that points to a segment middleware that it operates on and will be invoked before the actual route.
    ///
    /// We are using the separate `RouteTable` as the segments as we do want the abstraction that it provides, like the `get` methods, matching of the
    /// paths, suffixing with `index.html`, etc. also the insert method that check for duplication, even thought the duplication
    /// is not technically possible, as it would throw earlier.
    segments: RouteTable,
}

/// Middleware handlers will not give back the headers ownership as they are returning the context
/// that is passed further to the route handler.
///
/// Every change on the headers can be done by a mutable reference, as the context
/// is owned by value with headers also owned by value.
pub struct MiddlewareHandlerResult<'ctx> {
    // headers: HttpResponseHeaders<'b>,
    pub ctx: RouteContext<'ctx>,
}

impl Middleware {
    pub fn new() -> Self {
        Self {
            segments: RouteTable::new(),
            routes: RouteTable::new(),
        }
    }

    /// `NOTE`: This has to run after the routes are initialized.
    ///
    /// Runs on the routes declared on the `routes` field of the `Router` struct.
    ///
    /// Middleware segments collected from the route table. Parses the segments, removing the leading `:` character,
    ///
    /// NOTE: Technically we should make the segment generation run on insertion of the route, but that would require
    /// wrapper around the `RouteTable` to differentiate between the routes and middleware to define special behavior when we are
    /// inserting the route. We should do the same as we are doing there in the `Middleware::insert` to abstract it.
    /// Or we could just provide separate method for inserting the route in the `RouteTable` but I don't want to do that.
    /// So be aware that it runs O(n * m) where n is the number of routes in the `RouteTable` and m is the number of components in the path's of Routes.
    pub fn generate_middleware_segments(
        &mut self,
        routes: &Routes,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Returns the paths that are used for middleware.

        // We would generate O(1) look for the middleware segments
        // That maps each path to the corresponding segments that could be run on that path.
        // If the path given does exists in the segments, then there is no segment for that path.
        // It safes us some performance but utilizes more memory, not much though as we just allocate a clone the key and increase
        // the reference count of the RouteEntry handler.

        let mut segments = HashSet::<RouteTableKey>::new();
        // let mut segments_mapping: HashMap<RouteTableKey, RouteEntry> = HashMap::new();

        // Take the routes table, iterate and find the segments
        // For each path in the routes, try to match the segment path, there could be only one segment for this particular path.

        for key in self.routes.get_routes().keys() {
            let path = key.path.to_str().expect("Path should be valid UTF-8");

            if Middleware::is_path_segment(path) {
                let segment_key = RouteTableKey {
                    path: Middleware::parse_middleware_path(path),
                    method: key.method.clone(),
                };

                segments.insert(segment_key);
            }
        }

        for key in routes.get_routes().get_routes().keys() {
            let segment = Middleware::evaluate_to_segment(key, &segments);

            if let Some(segment) = segment {
                // If the segment is found, we add it to the mapping.

                let handler = self.routes.get_routes().get(&segment).map(|v| v.clone()).expect(
                    "Segment should exist in the routes as it was generated from them in the Middleware::evaluate_to_segment",
                );

                self.segments.insert(key.clone(), handler);
            }
        }

        Ok(())
    }

    /// Checks if the path is a segment path, meaning it starts with `:`.
    pub fn is_path_segment(path: &str) -> bool {
        // :pages => pages/:pages/index.html

        let p = Path::new(path);

        return path.starts_with(PATH_SEGMENT)
            && p.extension().is_none()
            && p != Path::new(PATH_SEGMENT)
            && p != Path::new(&format!("{}/", PATH_SEGMENT));
    }

    /// Given key of a route, it will try to match any segment that is defined in the `segments` set.
    ///
    /// It performs a search in reverse order, starting from the full path and removing one component at a time,
    /// until it finds a segment that matches the given key.
    ///
    /// For example: `database/tasks.json`, `database/tasks/tasks.json` for the segment `:database/tasks`
    /// will resolve to run on the path of `database/tasks/tasks.json` as that is the first, strongest match.
    ///
    /// On route key can have one segment that matches the given key, so it will return the first match.
    pub fn evaluate_to_segment(
        key: &RouteTableKey,
        segments: &HashSet<RouteTableKey>,
    ) -> Option<RouteTableKey> {
        let mut route = PathBuf::from(key.get_path());

        if route.extension().is_some() {
            route.pop();
        };

        let mut segment_key = RouteTableKey {
            path: route.clone(),
            method: key.method.clone(),
        };

        loop {
            if segments.contains(&segment_key) {
                segment_key.path = Self::path_to_segment(route.as_path());

                return Some(segment_key);
            }

            // Check if there is a segment handler for any method for that route.
            segment_key.method = None;

            if segments.contains(&segment_key) {
                segment_key.path = Self::path_to_segment(route.as_path());

                return Some(segment_key);
            }

            // Remove one component from the path, from the end.
            if !route.pop() {
                break;
            }

            // Update the path.
            segment_key.path = route.clone();
            // Revert the method to the original one.
            segment_key.method = key.method.clone();
        }

        None
    }

    /// Checks if the characters that have special meaning for the middleware paths are not percent encoded.
    ///
    /// NOTE: This have to run on the encoded path. The method can run on the routes
    /// without breaking, but that is considered unnecessary.
    ///
    /// NOTE: Actually the paths that are coming from the client should not be validated against it.
    /// If something that is considered as segment would end up in the path that are coming from the client,
    /// it should be normalized as usual and just resolve the path, do appropriate.
    /// This is more of a validation for the RouteTableKey paths that are statically defined in the code, more of a development time validation.
    pub fn validate_middleware_path(path: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        // If path is not a segment path, then it should be normalized.

        const PERCENT_ENCODED_COLON: &str = "%3A";

        if path.contains(&PERCENT_ENCODED_COLON.to_lowercase()) {
            return Err(Box::from(format!(
                "Path `{}` contains percent-encoded colon `{}` which is not allowed.",
                path, PERCENT_ENCODED_COLON
            )));
        };
        Ok(())
    }

    /// Middleware paths could have can have special characters that are used when resolving a path.
    ///
    // NOTE: Functionality can grow so we are implementing a method for that.
    pub fn parse_middleware_path(path: &str) -> PathBuf {
        // Parses the middleware path by removing the leading `:` segment if it exists.
        // This is used to normalize the path for middleware handling.

        // That is stupid, but I want to use the same piece of code that does the same logic
        // because if we would change the segment recognition logic, we would have to change it in two places.

        // safe to unwrap as we checked if the path starts with `:`
        if Middleware::is_path_segment(path) {
            return PathBuf::from(
                path.strip_prefix(PATH_SEGMENT)
                    // We want the "/" suffix to be removed as we will be using the Components API
                    // which strips the trailing slash from each component.
                    .and_then(|p| Some(p.strip_suffix("/").unwrap_or(p)))
                    .unwrap(),
            );
        }

        PathBuf::from(path)
    }

    pub fn path_to_segment(path: &Path) -> PathBuf {
        PathBuf::from(format!("{}{}/", PATH_SEGMENT, path.display()))
    }

    /// Validates the database "connection" for path that requested it and utilizes it.
    /// It won't run on every single path, but only on the paths that start with the `:database/` segment.
    pub fn validate_database(mut ctx: RouteContext) -> RouteHandlerFuture {
        Box::pin(async move {
            // Here we could initialize the database connection or any other resource
            // that we need for the middleware.

            let res = ctx.get_response_headers();

            res.add(
                "X-Database-Validation".into(),
                "Middleware executed for database validation".into(),
            );

            ctx.get_database().map_err(|e| {
                Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                    message: Some(
                        format!("Database not found for: {}", ctx.key.path.display()).to_string(),
                    ),
                    internals: Some(Box::<dyn Error + Send + Sync>::from(e)),
                    ..Default::default()
                })
            })?;

            return Ok(RouteResult::Middleware(MiddlewareHandlerResult { ctx }));
        })
    }

    pub fn insert(&mut self, key: RouteTableKey, entry: RouteEntry) {
        match &entry {
            RouteEntry::Middleware(handler) => match handler {
                Some(_) => {
                    let path_str = key.path.to_str().expect("Path should be valid UTF-8");

                    if let Err(e) = Middleware::validate_middleware_path(&path_str) {
                        panic!("Could not validate for middleware path: {:?}", e)
                    };

                    self.routes.insert(key, entry)
                }
                None => panic!(
                    "Middleware entry cannot be None while inserting the middleware entry duh."
                ),
            },
            RouteEntry::Route(_) => panic!(
                "Cannot insert a RouteEntry::Route into Middleware, only RouteEntry::Middleware is allowed."
            ),
        }
    }

    /// Creates the middleware routes and segments for the example paths.
    pub fn create_middleware(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // NOTE: Be aware that you can directly modify the RouteTable by invoking self.get_routes_mut().insert() which is invalid
        // as it does not check for the errors of the misuse of the RouteEntry and does not validate.

        self.insert(
            RouteTableKey::new("/", None),
            RouteEntry::Middleware(Some(RouteHandler::new(|mut ctx| {
                Box::pin(async move {
                    let headers = ctx.get_response_headers();

                    headers.add(
                        "X-Example-Middleware".into(),
                        "Middleware executed for /".into(),
                    );

                    Ok(RouteResult::Middleware(MiddlewareHandlerResult { ctx }))
                })
            }))),
        );

        self.insert(
            RouteTableKey::new(":database/", None),
            RouteEntry::Middleware(Some(RouteHandler::new(Middleware::validate_database))),
        );

        self.insert(
            RouteTableKey::new(":asd/", None),
            RouteEntry::Middleware(Some(RouteHandler::new(|ctx| {
                Box::pin(async move {
                    println!("Middleware for :asd/ called");

                    Ok(RouteResult::Middleware(MiddlewareHandlerResult { ctx }))
                })
            }))),
        );

        self.insert(
            RouteTableKey::new(":asd/data/asd asd/", None),
            RouteEntry::Middleware(Some(RouteHandler::new(|ctx| {
                Box::pin(async move {
                    println!("Middleware for :asd/data/asd asd/ called");

                    Ok(RouteResult::Middleware(MiddlewareHandlerResult { ctx }))
                })
            }))),
        );

        Ok(())
    }

    pub fn get_routes(&self) -> &RouteTable {
        // Returns the routes of the middleware.
        &self.routes
    }

    pub fn get_routes_mut(&mut self) -> &mut RouteTable {
        // Returns the mutable routes of the middleware.
        &mut self.routes
    }

    pub fn get_segments(&self) -> &RouteTable {
        // Returns the segments that are used for the middleware.
        &self.segments
    }

    pub fn get_segments_mut(&mut self) -> &mut RouteTable {
        // Returns the mutable segments that are used for the middleware.
        &mut self.segments
    }
}
