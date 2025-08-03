use std::{borrow::Cow, collections::HashMap};

use dashmap::DashMap;

use crate::{
    config::{config_file::DatabaseConfigEntry, database::Database},
    http::{
        HeaderMap, HttpProtocol, HttpRequestHeaders, HttpRequestRequestLine, HttpResponseHeaders,
        HttpResponseStartLine,
    },
    http_request::HttpRequest,
    prelude::*,
    router::{
        RouteContext, RouteHandlerResult, RouteResult, RouteTableKey,
        middleware::MiddlewareHandlerResult,
    },
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
///
/// If the body of the AppControllerResult and the RouteResult is the same, then this API is fine, if not, it would be disaster.
#[derive(Clone, Debug)]
pub enum RouterCacheResult<'ctx> {
    AppControllerResult(OptionalRouteResult<'ctx>),
    RouteResult(RouteResult<'ctx>),
}

// NOTE: Not sure if we would ever use the full output of the RouteResult, but technically we could
// thought as always with caching we have to be careful to not return stale data for routes that are doing validation or something
// that require fresh data.
// pub(in crate::router) static CACHE: Lazy<DashMap<RouteTableKey, RouterCacheResult>> =
// Lazy::new(DashMap::new);

/// A cache for storing route results. We had to declare the Owned API types here to avoid lifetimes issues, as the cache needs to live for static lifetime.
/// and we cannot guarantee that with the `RouteResult` type.
#[derive(Debug)]
pub struct RouterCache(DashMap<RouteTableKey, RouterCacheResult<'static>>);

// impl<'ctx> RouterCache<'ctx> {
impl RouterCache {
    pub fn new() -> Self {
        RouterCache(DashMap::new())
    }

    pub fn get(&self, key: &RouteTableKey) -> Option<RouterCacheResult<'static>> {
        // Get the value from the cache by key.
        // CACHE.get(key).map(|entry| entry.value().clone())
        // CACHE.get(key).map(|entry| entry.value().clone())
        // todo!()

        self.0.get(key).map(|entry| entry.value().clone())
    }

    /// We are storing the `RouteResult` for given key and using it later to avoid recomputing the route.
    pub fn set(&self, key: RouteTableKey, value: RouterCacheResult<'static>) {
        // Set the value in the cache by key.
        // CACHE.insert(key, value);
        self.0.insert(key, value);
    }

    pub fn remove(&self, key: &RouteTableKey) {
        // Remove the value from the cache by key.
        self.0.remove(key);
    }

    pub fn clear(&self) {
        // Clear the cache.
        // CACHE.clear();
        self.0.clear();
    }
}

#[derive(Clone, Debug)]
pub struct OwnedHttpRequest {
    pub headers: OwnedHttpRequestHeaders,
    pub body: Option<Vec<u8>>,
}

impl OwnedHttpRequest {
    pub fn to_borrowed<'a>(&'a self) -> HttpRequest<'a> {
        HttpRequest {
            headers: self.headers.to_borrowed(),
            body: self.body.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct OwnedHttpResponseStartLine {
    pub protocol: HttpProtocol,
    // status_code should be typed for all available status codes
    pub status_code: u16,
    pub status_text: Option<String>,
}

impl OwnedHttpResponseStartLine {
    pub fn to_borrowed<'a>(&'a self) -> HttpResponseStartLine<'a> {
        HttpResponseStartLine {
            protocol: self.protocol.clone(),
            status_code: self.status_code,
            status_text: self.status_text.as_deref(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OwnedHttpRequestHeaders {
    pub headers: OwnedHeaderMap,
    pub request_line: HttpRequestRequestLine,
}

impl OwnedHttpRequestHeaders {
    pub fn to_borrowed<'a>(&'a self) -> HttpRequestHeaders<'a> {
        HttpRequestHeaders {
            headers: self.headers.to_borrowed(),
            request_line: self.request_line.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct OwnedHeaderMap {
    pub headers: HashMap<String, String>,
}

impl OwnedHeaderMap {
    pub fn to_borrowed<'a>(&'a self) -> HeaderMap<'a> {
        // Allocates the vector of tuples from the HashMap, it holds the pointers of the headers, does not clone the strings.
        HeaderMap {
            headers: self
                .headers
                .iter()
                .map(|(k, v)| (Cow::Borrowed(k.as_str()), Cow::Borrowed(v.as_str())))
                .collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct OwnedHttpResponseHeaders {
    pub headers: OwnedHeaderMap,
    pub start_line: OwnedHttpResponseStartLine,
}

impl OwnedHttpResponseHeaders {
    pub fn to_borrowed<'a>(&'a self) -> HttpResponseHeaders<'a> {
        HttpResponseHeaders {
            headers: self.headers.to_borrowed(),
            start_line: self.start_line.to_borrowed(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct OwnedMiddlewareHandlerResult {
    pub ctx: OwnedRouteContext,
}

impl OwnedMiddlewareHandlerResult {
    pub fn to_borrowed<'a>(&'a self) -> MiddlewareHandlerResult<'a> {
        MiddlewareHandlerResult {
            ctx: self.ctx.to_borrowed(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct OwnedRouteContext {
    pub request: OwnedHttpRequest,
    pub response_headers: OwnedHttpResponseHeaders,
    pub key: RouteTableKey,
    pub database: Option<Arc<Mutex<Database>>>,
    pub database_config: Option<DatabaseConfigEntry>,
    pub cache: Arc<RouterCache>,
}

impl OwnedRouteContext {
    pub fn to_borrowed(&self) -> RouteContext {
        RouteContext {
            request: self.request.to_borrowed(),
            response_headers: self.response_headers.to_borrowed(),
            key: &self.key,
            database: self.database.as_ref().map(|d| Arc::clone(&d)),
            database_config: self.database_config.clone(),
            cache: Arc::clone(&self.cache),
        }
    }

    // // TODO: That is bad, we are redefining the same methods as in the RouteContext. To refactor.

    // pub fn get_response_headers(&mut self) -> &mut OwnedHttpResponseHeaders {
    //     // Returns the response headers of the route handler context.
    //     &mut self.response_headers
    // }

    // // Returns the key of the route handler context.
    // pub fn get_key(&self) -> &RouteTableKey {
    //     &self.key
    // }

    // pub fn get_database(&self) -> Result<Arc<Mutex<Database>>, Box<dyn Error + Send + Sync>> {
    //     // Returns the database of the route handler context.
    //     // Clones the Arc reference, cheap
    //     self.database
    //         .clone()
    //         .ok_or("Database is not initialized in the route handler context".into())
    // }

    // /// That would only return `None` if the `Database` is also `None`, if there is `database_config` there has to be `Database`,
    // /// if there is `Database` there has to be `database_config`.
    // pub fn get_database_config(&self) -> Result<DatabaseConfigEntry, Box<dyn Error + Send + Sync>> {
    //     // Returns the database config of the route handler context.
    //     // Clones the Arc reference, cheap
    //     self.database_config
    //         .clone()
    //         .ok_or("Database config is not initialized in the route handler context".into())
    // }
}

#[derive(Clone, Debug)]
pub struct OwnedRouteHandlerResult {
    pub headers: OwnedHttpResponseHeaders,
    pub body: String,
}

impl OwnedRouteHandlerResult {
    pub fn to_borrowed<'a>(&'a self) -> RouteHandlerResult<'a> {
        RouteHandlerResult {
            headers: self.headers.to_borrowed(),
            body: self.body.clone(),
        }
    }
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

impl OwnedRouteResult {
    pub fn to_borrowed<'a>(&'a self) -> RouteResult<'a> {
        match self {
            OwnedRouteResult::Route(result) => RouteResult::Route(result.to_borrowed()),
            OwnedRouteResult::Middleware(result) => RouteResult::Middleware(result.to_borrowed()),
        }
    }
}

// #[derive(Clone, Debug)]
// pub enum OptionalRouteResult {
//     Route(OptionalOwnedRouteHandlerResult),
//     Middleware(OwnedMiddlewareHandlerResult),
// }

#[derive(Clone, Debug)]
pub struct OptionalRouteHandlerResult<'ctx> {
    /// We are keeping it as optional, as the AppController handlers do not have to define headers in the cached output, although it could if it is costly to compute them.
    /// Keep in mind that the headers would have to be in-place initialized there and do not rely on the `response_headers` filed on the `RouteContext` struct,
    /// as they could not even be related.
    pub headers: Option<HttpResponseHeaders<'ctx>>,
    /// We actually have to keep the body as mandatory, and we will treat it in the AppController as the return type of the particular handler.
    pub body: String,
}

#[derive(Clone, Debug)]
pub enum OptionalRouteResult<'ctx> {
    Route(OptionalRouteHandlerResult<'ctx>),
    Middleware(MiddlewareHandlerResult<'ctx>),
}

// // // Wrapper around RouteContext and OwnedRouteContext to allow storing both borrowed and owned contexts in the same enum.
// #[derive(Clone, Debug)]
// pub enum RouteContextWrapper<'ctx> {
//     Borrowed(RouteContext<'ctx>),
//     Owned(OwnedRouteContext),
// }

// impl<'ctx> RouteContextWrapper<'ctx> {
//     pub fn to_borrowed(&self) -> RouteContext<'_> {
//         match self {
//             RouteContextWrapper::Borrowed(ctx) => ctx.clone(),
//             RouteContextWrapper::Owned(ctx) => ctx.to_borrowed(),
//         }
//     }
// }
