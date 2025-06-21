use std::{error::Error, future::Future, path::PathBuf, pin::Pin, sync::Arc};

use crate::routes::{RouteHandlerContext, RouteTable, RouteTableKey};

/// Middleware run before the actual request handler, and return the context that is passed later to the handler.
///
/// It also support the segment paths that would run if a path starts with the given segment.
///
/// for example, `:database/` would run for any path that starts with `database/`, like `database/users` or `database/transactions`.
pub struct Middleware;

/// The result of executing a middleware function.
pub type MiddlewareFunctionPointerResult<'b> =
    Result<RouteHandlerContext<'b>, Box<dyn Error + Send + Sync>>;

/// A function pointer representing a synchronous-style middleware.
pub type MiddlewareFunctionPointer =
    for<'b> fn(RouteHandlerContext<'b>) -> MiddlewareFunctionPointerResult<'b>;

/// The async version of a middleware — a boxed future resolving to a middleware result.
pub type MiddlewareClosureResult<'b> =
    Pin<Box<dyn Future<Output = MiddlewareFunctionPointerResult<'b>> + Send + 'b>>;

/// The actual middleware closure type — async-capable, shareable across threads/tasks.

pub type MiddlewareClosure =
    Arc<dyn for<'b> Fn(RouteHandlerContext<'b>) -> MiddlewareClosureResult<'b> + Send + Sync>;

#[derive(Clone)]
// 'a is the struct related things, 'b is the context
pub struct MiddlewareHandler(MiddlewareClosure);

impl MiddlewareHandler {
    pub fn new(handler: MiddlewareFunctionPointer) -> Self {
        Self(Self::wrap_handler(handler))
    }

    pub fn wrap_handler<'b>(handler: MiddlewareFunctionPointer) -> MiddlewareClosure {
        // Wraps the function pointer in an Arc to allow shared ownership.
        Arc::new(move |ctx| Box::pin(async move { handler(ctx) }))
    }

    pub async fn callback<'b>(
        &self,
        ctx: RouteHandlerContext<'b>,
    ) -> Result<RouteHandlerContext<'b>, Box<dyn Error + Send + Sync>> {
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
    pub fn init_database<'b>(ctx: RouteHandlerContext<'b>) -> MiddlewareFunctionPointerResult<'b> {
        // Here we could initialize the database connection or any other resource
        // that we need for the middleware.

        println!("Initializing database for context: {:?}", ctx);

        Ok(ctx)
    }

    pub fn create_middleware(routes: &mut RouteTable) {
        // It should be possible to use the unnormalized paths there
        routes.insert_middleware(
            RouteTableKey::new(PathBuf::from("pages/\\index.html"), None),
            MiddlewareHandler::new(|ctx| {
                println!(
                    "Middleware for pages/index.html called with context: {:?}",
                    ctx
                );

                Ok(ctx)
            }),
        );
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
