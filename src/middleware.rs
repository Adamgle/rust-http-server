use std::{
    collections::HashSet,
    error::Error,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use crate::{
    http::HttpRequestError,
    routes::{RouteHandlerContext, RouteTable, RouteTableKey},
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
    segments: HashSet<RouteTableKey>,
}

/// Middleware handlers will not give back the headers ownership as they are returning the context
/// that is passed further to the route handler.
///
/// Every change on the headers can be done by a mutable reference, as the context
/// is owned by value with headers also owned by value.
// `NOTE`: This could be type alias.
pub struct MiddlewareHandlerResult<'ctx> {
    // headers: HttpResponseHeaders<'b>,
    pub ctx: RouteHandlerContext<'ctx>,
}

/// The async version of a middleware — a boxed future resolving to a middleware result.
pub type MiddlewareHandlerFuture<'ctx> = Pin<
    Box<
        dyn Future<Output = Result<MiddlewareHandlerResult<'ctx>, Box<dyn Error + Send + Sync>>>
            + Send
            + 'ctx,
    >,
>;

/// The actual middleware closure type — async-capable, shareable across threads/tasks.

pub type MiddlewareClosure = Arc<
    dyn for<'ctx> Fn(RouteHandlerContext<'ctx>) -> MiddlewareHandlerFuture<'ctx>
        + Send
        + Sync
        + 'static,
>;

#[derive(Clone)]
pub struct MiddlewareHandler(MiddlewareClosure);
// 'a is the struct related things, 'ctx is the context

impl MiddlewareHandler {
    pub fn new<F>(handler: F) -> Self
    where
        F: Send + Sync + 'static,
        F: Fn(RouteHandlerContext) -> MiddlewareHandlerFuture,
    {
        Self(Arc::new(handler))
    }

    pub async fn callback<'ctx>(
        &self,
        ctx: RouteHandlerContext<'ctx>,
    ) -> Result<MiddlewareHandlerResult<'ctx>, Box<dyn Error + Send + Sync>> {
        // Call the middleware function pointer with the request, response headers, and key.

        (self.0)(ctx).await
    }
}

impl std::fmt::Debug for MiddlewareHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Custom debug implementation to show the function pointer address.
        f.debug_tuple("MiddlewareHandler")
            // That is impractical, it show the memory address of the dyn Trait
            .field(&Arc::as_ptr(&self.0))
            // .field(&Some(()))
            .finish()
    }
}

pub const PATH_SEGMENT: &str = ":";

impl Middleware {
    pub fn new(routes: &RouteTable) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Create a new middleware with the given segments.
        Ok(Self {
            segments: Self::generate_middleware_segments(routes)?,
        })
    }

    /// `NOTE`: This has to run after the routes are initialized.
    ///
    /// Middleware segments collected from the route table. Parses the segments, removing the leading `:` character,
    pub fn generate_middleware_segments(
        routes: &RouteTable,
    ) -> Result<HashSet<RouteTableKey>, Box<dyn Error + Send + Sync>> {
        // Returns the paths that are used for middleware.

        let mut segments = HashSet::new();

        for (key, value) in routes.get_routes().iter() {
            let path = key.get_path().to_str().expect("Path should be valid UTF-8");

            if value.get_middleware().is_some() && Middleware::is_path_segment(path) {
                let key = RouteTableKey::new_no_validate(
                    Middleware::parse_middleware_path(path),
                    key.get_method().clone(),
                );
                segments.insert(key);
            }
        }

        Ok(segments)
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
    // NOTE:  Functionality can grow so we are implementing a method for that.
    pub fn parse_middleware_path(path: &str) -> PathBuf {
        // Parses the middleware path by removing the leading `:` segment if it exists.
        // This is used to normalize the path for middleware handling.

        // That is stupid, but I want to use the same piece of code that does the same logic
        // because if we would change the segment recognition logic, we would have to change it in two places.

        if Middleware::is_path_segment(path) {
            // safe to unwrap as we checked if the path starts with `:`
            return PathBuf::from(
                path.strip_prefix(PATH_SEGMENT)
                    // We want the "/" suffix to be removed as we will be using the Components API
                    // which strips the trailing slash from each component.
                    .and_then(|p| Some(p.strip_suffix("/").unwrap_or(p)))
                    .unwrap(),
            );
        }

        return PathBuf::from(path);
    }

    /// Validates the database "connection" for path that requested it and utilizes it.
    /// It won't run on every single path, but only on the paths that start with the `:database/` segment.
    pub fn validate_database(mut ctx: RouteHandlerContext) -> MiddlewareHandlerFuture {
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

            return Ok(MiddlewareHandlerResult { ctx });
        })
    }

    pub fn create_middleware(routes: &mut RouteTable) {
        // It should be possible to use the unnormalized paths there
        routes.insert_middleware(
            // pages/\\index.html => Should be normalized.
            RouteTableKey::new("/", None),
            MiddlewareHandler::new(|mut ctx| {
                Box::pin(async move {
                    let headers = ctx.get_response_headers();

                    headers.add(
                        "X-Example-Middleware".into(),
                        "Middleware executed for /".into(),
                    );

                    Ok(MiddlewareHandlerResult { ctx })
                })
            }),
        );

        // The trailing slash since without it we would not know if that is a directory or a filename, because there could also be
        // extension attached to the database and that would still match, like database.rs.
        routes.insert_middleware(
            RouteTableKey::new(":database/", None),
            MiddlewareHandler::new(Middleware::validate_database),
        );

        routes.insert_middleware(
            RouteTableKey::new(":asd/", None),
            MiddlewareHandler::new(|ctx| {
                Box::pin(async move {
                    // let headers = ctx.get_response_headers();

                    // Here we could do some validation or initialization
                    // For example, we could check if the database is available or not.

                    Ok(MiddlewareHandlerResult { ctx })
                })
            }),
        );

        routes.insert_middleware(
            RouteTableKey::new(":asd/data/asd asd/", None),
            MiddlewareHandler::new(|mut ctx| {
                Box::pin(async move {
                    println!("Stronger path");

                    let headers = ctx.get_response_headers();

                    headers.add(
                        "X-Example-Middleware".into(),
                        "Middleware executed for :asd/data/asd asd/".into(),
                    );

                    // Here we could do some validation or initialization
                    // For example, we could check if the database is available or not.

                    Ok(MiddlewareHandlerResult { ctx })
                })
            }),
        )
    }

    pub fn path_to_segment(path: &Path) -> PathBuf {
        // Converts the path to a segment by removing the leading `:` character if it exists.
        // This is used to normalize the path for middleware handling.

        PathBuf::from(format!("{}{}{}", PATH_SEGMENT, path.display(), "/"))
    }

    pub fn get_segments(&self) -> &HashSet<RouteTableKey> {
        // Returns the segments that are used for the middleware.
        &self.segments
    }

    /// This is evaluated at runtime while processing the request, compared to the other API that is evaluated on server startup.
    ///
    /// The lookup for the segments will be O(n), where n is the number of components in the path
    /// that comes from the client.
    ///
    /// Segments should be resolved in the order of their strength, so the more specific segment would run on the path.
    /// :database/ => database/*
    /// :database/tasks/ => This segment is stronger, so it should run on the paths containing database/tasks, :database should not run.
    ///
    /// `NOTE`: We can opt out of the behavior of the strength of the segment and just run every segment that matches.
    pub fn is_segment(
        &self,
        key: &RouteTableKey,
    ) -> Result<Option<RouteTableKey>, Box<dyn Error + Send + Sync>> {
        let path = key.get_path();

        let path =
            Middleware::parse_middleware_path(path.to_str().expect("Path should be valid UTF-8"));

        let method = key.get_method();

        let segments = self.get_segments();
        let mut segment = PathBuf::from(path);

        if segment.extension().is_some() {
            segment.pop();
        };

        loop {
            let segment_key = RouteTableKey::new_no_validate(&segment, method.clone());

            if segments.contains(&segment_key) {
                // If the segment is found in the middleware segments, return it.

                return Ok(Some(RouteTableKey::new_no_validate(
                    Self::path_to_segment(&segment),
                    key.get_method().clone(),
                )));
            }

            if !segment.pop() {
                break;
            }
        }

        Ok(None)
    }
}
