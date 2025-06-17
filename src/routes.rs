use std::{collections::HashMap, error::Error, path::PathBuf};

use crate::{
    config::SpecialDirectories,
    http::{HttpRequestMethod, HttpResponseHeaders},
    http_request::HttpRequest,
};

fn _main() {
    let outer_var = 42;

    // A regular function can't refer to variables in the enclosing environment
    //fn function(i: i32) -> i32 { i + outer_var }
    // TODO: uncomment the line above and see the compiler error. The compiler
    // suggests that we define a closure instead.

    // Closures are anonymous, here we are binding them to references.
    // Annotation is identical to function annotation but is optional
    // as are the `{}` wrapping the body. These nameless functions
    // are assigned to appropriately named variables.
    let closure_annotated = |i: i32| -> i32 { i + outer_var };
    let closure_inferred = |i| i + outer_var;

    // Call the closures.
    println!("closure_annotated: {}", closure_annotated(1));
    println!("closure_inferred: {}", closure_inferred(1));
    // Once closure's type has been inferred, it cannot be inferred again with another type.
    //println!("cannot reuse closure_inferred with another type: {}", closure_inferred(42i64));
    // TODO: uncomment the line above and see the compiler error.

    // A closure taking no arguments which returns an `i32`.
    // The return type is inferred.
    let one = || 1;
    println!("closure returning one: {}", one());
}

// NOTE: Route table does live for the duration of the program, but not the values it is referencing.
// whatever we put in the route table is valid for static, but not the values it is referencing.
// We need to copy that values to put it in the route table because values it is referencing are not
// static and will be wasted from memory after request is done.

// NOTE: Lifetimes are not practically even in this code, as the RouteTable does not have not tied
// the request and response headers to the lifetime of struct, it is independent and those values lives shorter lifetime.

pub struct RouteTable(HashMap<RouteTableKey, RouteHandler>);

/// Routing table lives for the whole lifetime of the server, since path is a `static` lifetime.
#[derive(Hash, Eq, PartialEq)]
pub struct RouteTableKey(PathBuf, HttpRequestMethod);

pub struct RouteHandlerContext<'a>(
    // Lifetimes there may be mistaken as the request and response headers
    // are getting dropped after the request is done, but here you said
    // it is valid for 'a.
    &'a mut HttpRequest<'a>,
    &'a mut HttpResponseHeaders<'a>,
    Option<PathBuf>,
);

// const ROUTER_HANDLER_REQUEST_CONTEXT: &str = "_ctx";

/// A function pointer that mutates the `HttpRequest` and `HttpResponseHeaders` on successful request.
///
/// RouterHandler will also carry additional context in the headers.
pub type RouteHandler = Box<
    // for all lifetimes 'a, we can use the same function signature
    dyn for<'a> Fn(RouteHandlerContext<'a>) -> Result<String, Box<dyn Error + Send + Sync>>
        + Send
        + Sync,
>;

impl RouteTable {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn static_route_handler(
        ctx: RouteHandlerContext<'_>,
        // req: &mut HttpRequest,
        // res_headers: &mut HttpResponseHeaders,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let RouteHandlerContext(req, res, path) = ctx;

        // Ensure we have a path to work with, either from the context or from the request itself.
        let path = match path {
            Some(p) => p,
            None => req.get_request_target_path()?,
        };

        Ok(req.read_requested_resource(res, &path)?)
    }

    // We get a path to the function
    pub fn create_routes(
    ) -> Result<Option<HashMap<RouteTableKey, RouteHandler>>, Box<dyn Error + Send + Sync>> {
        // We have the routes cached in the file that is composed in runtime and parsed to some context at startup.
        // We check if the path exists the cached routes or is that a new route that we have defined in the code in that function.

        // 1. We did not found the path => We have to evaluate every path also by instantiating the handler function
        //  -> which is a closure and that would capture it's environment occupying some memory. That would be a O(n) operation to search for route. We can't allow that.
        // 2. We did found the path => ACTUALLY: As I am thinking about that, we either way would have to evaluate each handler function making that design.
        //  -> only way we would not is a match statement that would be a O(1) operation.

        // We will not store the closures in the routes as that would waste memory as we have to evaluate the whole table of routes
        // on startup or when the first request comes in. We would use function pointers, that would be only 8 bits per function on x64 architecture.

        // let mut paths = std::collections::HashSet::<(&str, HttpRequestMethod)>::new();

        let RouteTable(mut routes) = RouteTable::new();
        // Every path in the SpecialDirectories can be routed without authentication using GET method.

        SpecialDirectories::collect()
            .inspect_err(|e| {
                eprintln!("Failed to collect static routes: {}", e);
            })?
            .into_iter()
            .for_each(|(path, method)| {
                // We are using a closure here to capture the context of the request and response headers.
                let handler =
                    Box::new(|ctx: RouteHandlerContext<'_>| Self::static_route_handler(ctx));

                routes.insert(RouteTableKey(path, method), handler);
            });

        Ok(Some(routes))
    }
    pub fn route(
        key: (&str, &HttpRequestMethod),
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}
