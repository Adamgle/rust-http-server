use std::{
    error::Error,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use crate::routes::{MiddlewareHandler, RouteHandlerContext, RouteTable, RouteTableKey};

/// The result of executing a middleware function.
pub type MiddlewareFunctionPointerResult<'a> =
    Result<RouteHandlerContext<'a>, Box<dyn Error + Send + Sync>>;

/// A function pointer representing a synchronous-style middleware.
pub type MiddlewareFunctionPointer =
    for<'a> fn(RouteHandlerContext<'a>) -> MiddlewareFunctionPointerResult<'a>;

/// The async version of a middleware — a boxed future resolving to a middleware result.
pub type MiddlewareClosureResult<'a> =
    Pin<Box<dyn Future<Output = MiddlewareFunctionPointerResult<'a>> + Send + 'a>>;

/// The actual middleware closure type — async-capable, shareable across threads/tasks.

pub type MiddlewareClosure =
    Arc<dyn for<'a> Fn(RouteHandlerContext<'a>) -> MiddlewareClosureResult<'a> + Send + Sync>;

/// Middleware run before the actual request handler, and return the context that is passed later to the handler.
///
/// It also support the segment paths that would run if a path starts with the given segment.
///
/// for example, `:database/` would run for any path that starts with `database/`, like `database/users` or `database/transactions`.
pub struct Middleware;

pub const PATH_SEGMENT: &str = ":";

impl Middleware {
    pub fn init_database<'a>(ctx: RouteHandlerContext<'a>) -> MiddlewareFunctionPointerResult<'a> {
        // Here we could initialize the database connection or any other resource
        // that we need for the middleware.

        println!("Initializing database for context: {:?}", ctx);

        Ok(ctx)
    }

    pub fn create_middleware(routes: &mut RouteTable) {
        // It should be possible to use the unnormalized paths there
        // routes.insert_middleware(
        //     RouteTableKey::new(Path::new("database/"), None),
        //     MiddlewareHandler::new(Middleware::init_database),
        // );

        // If path starts with ":" then we will execute that code for every path that starts
        // with prefix after the ":", ":database/" => "database/" => Would run on "database/tasks.json", etc..

        // This should resolve to "database/" segment and run on every single path that starts with "database/"
        // The trailing slash since without it we would not know if that is a directory or a filename, because there could also be
        // extension attached to the database and that would still match, like database.rs.
        routes.insert_middleware(
            RouteTableKey::new(PathBuf::from(":database/"), None),
            MiddlewareHandler::new(Middleware::init_database),
        )
    }
}
