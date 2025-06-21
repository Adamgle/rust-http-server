use std::{error::Error, future::Future, path::PathBuf, pin::Pin, sync::Arc};

use crate::routes::{RouteHandlerContext, RouteTable, RouteTableKey};

/// Middleware run before the actual request handler, and return the context that is passed later to the handler.
///
/// It also support the segment paths that would run if a path starts with the given segment.
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
pub struct MiddlewareHandlerResult<'b> {
    // headers: HttpResponseHeaders<'b>,
    pub ctx: Result<RouteHandlerContext<'b>, Box<dyn Error + Send + Sync>>,
}

/// The result of executing a middleware function.
// pub type MiddlewareFunctionPointerResult<'ctx> =
//     Result<RouteHandlerContext<'ctx>, Box<dyn Error + Send + Sync>>;

/// A function pointer representing a synchronous-style middleware.
// pub type MiddlewareFunctionPointer =
//     for<'ctx> fn(RouteHandlerContext<'ctx>) -> MiddlewareFunctionPointerResult<'ctx>;

/// The async version of a middleware — a boxed future resolving to a middleware result.
pub type MiddlewareHandlerFuture<'ctx> =
    Pin<Box<dyn Future<Output = MiddlewareHandlerResult<'ctx>> + Send + 'ctx>>;

/// The actual middleware closure type — async-capable, shareable across threads/tasks.

pub type MiddlewareClosure = Arc<
    dyn for<'ctx> Fn(RouteHandlerContext<'ctx>) -> MiddlewareHandlerFuture<'ctx>
        + Send
        + Sync
        + 'static,
>;

#[derive(Clone)]
// 'a is the struct related things, 'ctx is the context
pub struct MiddlewareHandler(MiddlewareClosure);

impl MiddlewareHandler {
    pub fn new(handler: fn(RouteHandlerContext<'_>) -> MiddlewareHandlerResult<'_>) -> Self {
        let c: MiddlewareClosure = Arc::new(move |ctx| {
            // Convert the function pointer to a boxed future.
            Box::pin(async move {
                // Call the handler with the context and return the result.
                handler(ctx)
            })
        });
        Self(c)
    }

    // pub fn wrap_handler<'ctx>(handler: MiddlewareFunctionPointer) -> MiddlewareClosure {
    //     // Wraps the function pointer in an Arc to allow shared ownership.
    //     Arc::new(move |ctx| Box::pin(async move { handler(ctx) }))
    // }

    pub async fn callback<'ctx>(
        &self,
        ctx: RouteHandlerContext<'ctx>,
    ) -> MiddlewareHandlerResult<'ctx> {
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
    pub fn init_database(mut ctx: RouteHandlerContext) -> MiddlewareHandlerResult {
        // Here we could initialize the database connection or any other resource
        // that we need for the middleware.

        let _res_headers = ctx.get_response_headers();

        // There you do some processing on headers if you want to.

        return MiddlewareHandlerResult { ctx: Ok(ctx) };
    }

    pub fn create_middleware(routes: &mut RouteTable) {
        // It should be possible to use the unnormalized paths there
        routes.insert_middleware(
            // pages/\\index.html => Should be normalized.
            RouteTableKey::new(PathBuf::from("pages/index.html"), None),
            MiddlewareHandler::new(|ctx| {
                println!(
                    "Middleware for pages/index.html called with context: {:?}",
                    ctx
                );

                MiddlewareHandlerResult { ctx: Ok(ctx) }
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
