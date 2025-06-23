use std::{any::Any, error::Error, future::Future, path::PathBuf, pin::Pin, sync::Arc};

use crate::{
    http::HttpRequestError,
    routes::{RouteHandlerContext, RouteResult, RouteTable, RouteTableKey},
};

use crate::http::HttpHeaders;

/// Middleware run before the actual request handler, and return the context that is passed later to the handler.
///
/// It works on the paths or segments of the path that are prefixed with `:` character.
///
/// for example, `:database/` would run for any path that starts with `database/`, like `database/users` or `database/transactions`.
pub struct Middleware;

/// Middleware handlers will not give back the headers ownership as they are returning the context
/// that is passed further to the route handler.
///
/// Every change on the headers can be done by a mutable reference, as the context \
/// is owned by value with headers also owned by value.
///
// `NOTE`: This could be type alias.
pub struct MiddlewareHandlerResult<'ctx> {
    // headers: HttpResponseHeaders<'b>,
    pub ctx: RouteHandlerContext<'ctx>,
}

impl<'ctx> RouteResult<'ctx> for MiddlewareHandlerResult<'ctx> {
    fn as_any(&self) -> &(dyn Any + 'ctx) {
        self
    }
}

/// The result of executing a middleware function.
// pub type MiddlewareFunctionPointerResult<'ctx> =
//     Result<RouteHandlerContext<'ctx>, Box<dyn Error + Send + Sync>>;

/// A function pointer representing a synchronous-style middleware.
// pub type MiddlewareFunctionPointer =
//     for<'ctx> fn(RouteHandlerContext<'ctx>) -> MiddlewareFunctionPointerResult<'ctx>;

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

    /// Checks if the path is a segment path, meaning it starts with `:`.
    pub fn is_path_segment(path: &str) -> bool {
        // If path would not be converted to string:
        // Path will be prefixed with directory, but the check requires that the path starts with `:`.
        // We would have to check if the path is prefixed, if surely that is the directory and only on the first position
        // then the next segment after that would have to start with `:`.

        // We will just convert to string, we are doing that either way in constructor and if not UTF-8 compatible that would an error.
        // path.components()
        //     // <Component<'_> as AsRef<T>>::as_ref(&`, `)`
        //     .any(|c| {
        //         c.as_os_str()
        //             .to_str()
        //             .expect("Path not UTF-8 compatible.")
        //             .to_string()
        //             .starts_with(PATH_SEGMENT)
        //     })

        // We need to check there is not extension, then that implies there is no file, we have to because segments does nto work on files, only on "directories".
        // Segments are disallowed on special directories
        // Path that I am working on are already normalized.

        // :pages => pages/:pages/index.html

        path.starts_with(PATH_SEGMENT)
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

        if path.contains(PERCENT_ENCODED_COLON) {
            return Err(Box::from(format!(
                "Path `{}` contains percent-encoded colon `{}` which is not allowed.",
                path, PERCENT_ENCODED_COLON
            )));
        };

        Ok(())
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
            RouteTableKey::new(":asd/data/asd asd/", None),
            MiddlewareHandler::new(|mut ctx| {
                Box::pin(async move {
                    println!("Middleware for :asd/data/asd asd/");

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
}
