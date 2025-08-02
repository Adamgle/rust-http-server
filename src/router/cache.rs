use dashmap::DashMap;
use once_cell::sync::Lazy;

use crate::{
    config::{config_file::DatabaseConfigEntry, database::Database},
    http::{HttpProtocol, HttpRequestRequestLine},
    prelude::*,
    router::RouteTableKey,
};

// Goals for RouterCache:
// - Store the result of the [route handler] to avoid recomputing it for the same key.
// - Use the cache to speed up the response time for frequently accessed routes.
// - Ensure that the cache is thread-safe and can be accessed concurrently, we are using DashMap for that.
// - Provide a way of caching not only the route results, but the API that is exposed through AppController. That would be a challenge, as the AppController does not have
//  => a fixed signature and we cannot easily type it. Also we would have to define some wrapper for the AppController methods and the route handlers, as I would imagine that
//  => they would not share the signature, also we need some differentiation for those, likely an enum. By signature I mean the return type, of course we do not want to cache the
//  => function pointers itself, just the result of those.

/*

// There could be different sources of the results there, the one in the AppController without a fixed return type and there we would have to assume for those to return serialized whatever to String,
// and then we would deserialize accordingly, thought be aware that that is not ideal, as the responsibility to deserialize to the correct type lays on the developer.
enum RouterCacheResult {
        // For AppController I would allow the manipulation of the headers and the body, and keep it optional, meaning the AppController abstraction could define the headers
        // in some way and the body as well, but it is not required to do so. Of course doing nothing would be a valid response, thought useless to cache.
        AppControllerResult(OwnedRouteResult => { Route -> { headers: Option<OwnedHttpResponseHeaders>, body: Option<String> } | Middleware -> { ctx: OwnedRouteContext } })
        RouteResult(OwnedRouteResult) => { Route -> { headers: OwnedHttpResponseHeaders, body: String } | Middleware -> { ctx: OwnedRouteContext } })
    }
*/

/// The RouterCacheResult could fall into two stages. First whatever is cached in the AppController and then for the route handlers.
/// Although that is not common for the AppController to also be exposed as a route handler, it can act as a intermediate stage, for example the AppController handler could
/// compute the body of the route handler, and we would want to cache that result, and knowing that the handler of the AppController is commonly called, we would want to cache that result.
/// In this way we could cache for the AppController handlers and the route handlers.
///
/// The biggest issue with the cache for me is that we do not know what type the body really is, and we need to really on the developer knowledge to return the correct type and deserialize accordingly.
#[derive(Clone, Debug)]
pub enum RouterCacheResult {
    AppControllerResult(OptionalRouteResult),
    RouteResult(OwnedRouteResult),
}

/// A cache for storing route results. We had to declare the Owned API types here to avoid lifetimes issues, as the cache needs to live for static lifetime.
/// and we cannot guarantee that with the `RouteResult` type.
pub struct RouterCache;

// NOTE: Not sure if we would ever use the full output of the RouteResult, but technically we could
// thought as always with caching we have to be careful to not return stale data for routes that are doing validation or something
// that require fresh data.
pub(in crate::router) static CACHE: Lazy<DashMap<RouteTableKey, RouterCacheResult>> =
    Lazy::new(DashMap::new);

impl RouterCache {
    pub fn get(key: &RouteTableKey) -> Option<RouterCacheResult> {
        // Get the value from the cache by key.
        // CACHE.get(key).map(|entry| entry.value().clone())
        CACHE.get(key).map(|entry| entry.value().clone())
    }

    /// We are storing the `RouteResult` for given key and using it later to avoid recomputing the route.
    pub fn set(key: RouteTableKey, value: RouterCacheResult) {
        // Set the value in the cache by key.
        CACHE.insert(key, value);
    }

    pub fn remove(key: &RouteTableKey) {
        // Remove the value from the cache by key.
        CACHE.remove(key);
    }

    pub fn clear() {
        // Clear the cache.
        CACHE.clear();
    }
}

#[derive(Clone, Debug)]
pub struct OwnedHttpRequest {
    pub headers: OwnedHttpRequestHeaders,
    pub body: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct OwnedHttpResponseStartLine {
    pub protocol: HttpProtocol,
    // status_code should be typed for all available status codes
    pub status_code: u16,
    pub status_text: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OwnedHttpRequestHeaders {
    pub headers: OwnedHeaderMap,
    pub request_line: HttpRequestRequestLine,
}

#[derive(Clone, Debug)]
pub struct OwnedHeaderMap {
    pub headers: DashMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct OwnedHttpResponseHeaders {
    pub headers: OwnedHeaderMap,
    pub start_line: OwnedHttpResponseStartLine,
}

#[derive(Clone, Debug)]
pub struct OwnedMiddlewareHandlerResult {
    pub ctx: OwnedRouteContext,
}

#[derive(Clone, Debug)]
pub struct OwnedRouteContext {
    pub request: OwnedHttpRequest,
    pub response_headers: OwnedHttpResponseHeaders,
    pub key: RouteTableKey,
    pub database: Option<Arc<Mutex<Database>>>,
    pub database_config: Option<DatabaseConfigEntry>,
}

#[derive(Clone, Debug)]
pub struct OwnedRouteHandlerResult {
    pub headers: OwnedHttpResponseHeaders,
    pub body: String,
}

#[derive(Clone, Debug)]
pub struct OptionalOwnedRouteHandlerResult {
    /// We are keeping it as optional, as the AppController handlers do not have to define headers in the cached output, although it could if it is costly to compute them.
    /// Keep in mind that the headers would have to be in-place initialized there and do not rely on the `response_headers` filed on the `OwnedRouteContext` struct,
    /// as they could not even be related.
    pub headers: Option<OwnedHttpResponseHeaders>,
    /// We actually have to keep the body as mandatory, and we will treat it in the AppController as the return type of the particular handler.
    pub body: String,
}

#[derive(Clone, Debug)]
pub enum OwnedRouteResult {
    Route(OwnedRouteHandlerResult),
    Middleware(OwnedMiddlewareHandlerResult),
}

#[derive(Clone, Debug)]
pub enum OptionalRouteResult {
    Route(OptionalOwnedRouteHandlerResult),
    Middleware(OwnedMiddlewareHandlerResult),
}

// TODO: Think about implementing a constructor for that type.
// impl OptionalRouteResult {
//     pub fn into_owned(self) -> OwnedRouteResult {
//         match self {
//             RouteResult::Route(result) => OwnedRouteResult::Route(OwnedRouteHandlerResult {
//                 headers: result.headers.into_owned(),
//                 body: result.body,
//             }),
//             RouteResult::Middleware(result) => {
//                 OwnedRouteResult::Middleware(OwnedMiddlewareHandlerResult {
//                     ctx: result.ctx.into_owned(),
//                 })
//             }
//         }
//     }
// }
