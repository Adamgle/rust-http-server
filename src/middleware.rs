use std::{
    collections::{HashMap, HashSet},
    error::Error,
    path::{Path, PathBuf},
};

use crate::{
    http::HttpRequestError,
    routes::{
        RouteContext, RouteEntry, RouteHandler, RouteHandlerFuture, RouteKeyKind, RouteResult,
        RouteTable, RouteTableKey,
    },
};

use crate::http::HttpHeaders;

/// Middleware run before the actual request handler, and return the context that is passed later to the handler.
///
/// It works on the paths or segments of the path that are prefixed with `:` character.
///
/// for example, `:database/` would run for any path that starts with `database/`, like `database/users` or `database/transactions`.
#[derive(Debug)]
pub struct Middleware {
    // NOTE: Make sure that static is valid, seems valid.
    pub routes: RouteTable,
    // We could statically generate those segments to every single path
    // that would evaluate to particular segment handler,
    // HashMap<RouteTableKey, RouteHandler>,
    /// NOTE: Route entry should be of RouteEntry::Middleware variant.
    pub segments: HashMap<RouteTableKey, RouteEntry>,
}

/// Middleware handlers will not give back the headers ownership as they are returning the context
/// that is passed further to the route handler.
///
/// Every change on the headers can be done by a mutable reference, as the context
/// is owned by value with headers also owned by value.
// `NOTE`: This could be type alias.
pub struct MiddlewareHandlerResult<'ctx> {
    // headers: HttpResponseHeaders<'b>,
    pub ctx: RouteContext<'ctx>,
}

pub const PATH_SEGMENT: &str = ":";

impl Middleware {
    pub fn new(routes: &RouteTable) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Create a new middleware with the given segments.

        let middleware_routes = Self::create_middleware()?;

        Ok(Self {
            segments: Self::generate_middleware_segments(routes, &middleware_routes)?,
            routes: middleware_routes,
        })
    }

    /// `NOTE`: This has to run after the routes are initialized.
    ///
    /// Runs on the routes declared on the `routes` field of the `Router` struct.
    ///
    /// Middleware segments collected from the route table. Parses the segments, removing the leading `:` character,
    pub fn generate_middleware_segments(
        routes: &RouteTable,
        middleware_routes: &RouteTable,
    ) -> Result<HashMap<RouteTableKey, RouteEntry>, Box<dyn Error + Send + Sync>> {
        // Returns the paths that are used for middleware.

        // We would generate O(1) look for the middleware segments
        // That maps each path to the corresponding segments that could be run on that path.
        // If the path given does exists in the segments, then there is no segment for that path.

        let mut segments = HashSet::<RouteTableKey>::new();
        let mut segments_mapping: HashMap<RouteTableKey, RouteEntry> = HashMap::new();

        // Take the routes table, iterate and find the segments
        // For each path in the routes, try to match the segment path, there could be only one segment for this particular path.

        for key in middleware_routes.get_routes().keys() {
            let path = key.get_path().to_str().expect("Path should be valid UTF-8");

            if Middleware::is_path_segment(path) {
                let segment_key = RouteTableKey::new_no_validate(
                    Middleware::parse_middleware_path(path),
                    key.get_method().clone(),
                    RouteKeyKind::Middleware,
                );

                segments.insert(segment_key);
            }
        }

        for key in routes.get_routes().keys() {
            let segment = Middleware::evaluate_to_segment(key, &segments);

            if let Some(segment) = segment {
                // If the segment is found, we add it to the mapping.

                let handler = middleware_routes.get(&segment)?;

                segments_mapping.insert(key.clone(), handler);
            }
        }

        Ok(segments_mapping)
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

    pub fn evaluate_to_segment(
        key: &RouteTableKey,
        segments: &HashSet<RouteTableKey>,
    ) -> Option<RouteTableKey> {
        let mut route = PathBuf::from(key.get_path());

        if route.extension().is_some() {
            route.pop();
        };

        let mut segment_key = RouteTableKey::new_no_validate(
            &route,
            key.get_method().clone(),
            RouteKeyKind::Middleware,
        );

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
            segment_key.method = key.get_method().clone();
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

        // if Middleware::is_path_segment(path) {
        // safe to unwrap as we checked if the path starts with `:`
        return PathBuf::from(
            path.strip_prefix(PATH_SEGMENT)
                // We want the "/" suffix to be removed as we will be using the Components API
                // which strips the trailing slash from each component.
                .and_then(|p| Some(p.strip_suffix("/").unwrap_or(p)))
                .unwrap(),
        );
        // }
    }

    pub fn path_to_segment(path: &Path) -> PathBuf {
        PathBuf::from(format!("{}{}{}", PATH_SEGMENT, path.display(), "/"))
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
                        format!(
                            "Database not found for: {}",
                            ctx.get_key().get_path().display()
                        )
                        .to_string(),
                    ),
                    internals: Some(Box::<dyn Error + Send + Sync>::from(e)),
                    ..Default::default()
                })
            })?;

            return Ok(RouteResult::Middleware(MiddlewareHandlerResult { ctx }));
        })
    }

    pub fn create_middleware() -> Result<RouteTable, Box<dyn Error + Send + Sync>> {
        let mut routes = RouteTable::new();

        routes.insert(
            RouteTableKey::new("/", None, RouteKeyKind::Middleware),
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

        routes.insert(
            RouteTableKey::new(":database/", None, RouteKeyKind::Middleware),
            RouteEntry::Middleware(Some(RouteHandler::new(Middleware::validate_database))),
        );

        routes.insert(
            RouteTableKey::new(":asd/", None, RouteKeyKind::Middleware),
            RouteEntry::Middleware(Some(RouteHandler::new(|ctx| {
                println!("Evaluating middleware for :asd/");

                Box::pin(
                    async move { Ok(RouteResult::Middleware(MiddlewareHandlerResult { ctx })) },
                )
            }))),
        );

        routes.insert(
            RouteTableKey::new(":asd/data/asd asd/", None, RouteKeyKind::Middleware),
            RouteEntry::Middleware(Some(RouteHandler::new(|ctx| {
                Box::pin(async move {
                    println!("Evaluating middleware for :asd/data/asd asd/");

                    Ok(RouteResult::Middleware(MiddlewareHandlerResult { ctx }))
                })
            }))),
        );

        Ok(routes)
    }

    // Converts the path to a segment by removing the leading `:` character if it exists.
    // This is used to normalize the path for middleware handling.

    pub fn get_segments(&self) -> &HashMap<RouteTableKey, RouteEntry> {
        // Returns the segments that are used for the middleware.
        &self.segments
    }

    // This is evaluated at runtime while processing the request, compared to the other API that is evaluated on server startup.
    //
    // The lookup for the segments will be O(n), where n is the number of components in the path
    // that comes from the client.
    //
    // Segments should be resolved in the order of their strength, so the more specific segment would run on the path.
    // :database/ => database/*
    // :database/tasks/ => This segment is stronger, so it should run on the paths containing database/tasks, :database should not run.
    //
    // `NOTE`: We can opt out of the behavior of the strength of the segment and just run every segment that matches.
}
