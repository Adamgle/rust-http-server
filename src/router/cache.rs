use std::{borrow::Cow, collections::HashMap};

use dashmap::DashMap;
use horrible_database::{Database, DatabaseConfigEntry};
use once_cell::sync::Lazy;

use crate::{
    http::{
        HeaderMap, HttpProtocol, HttpRequestHeaders, HttpRequestRequestLine, HttpResponseHeaders,
        HttpResponseStartLine,
    },
    http_request::HttpRequest,
    prelude::*,
    router::{RouteContext, RouteHandlerResult, RouteTableKey},
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
#[derive(Clone)]
pub enum RouterCacheResult {
    AppControllerResult(OptionalOwnedRouteHandlerResult),
    RouteResult(OwnedRouteHandlerResult),
}

impl std::fmt::Debug for RouterCacheResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouterCacheResult::AppControllerResult(result) => f
                .debug_struct("AppControllerResult")
                .field(
                    "headers",
                    &result.headers.as_ref().map(|h| {
                        h.headers
                            .headers
                            .iter()
                            .map(|(k, v)| (k, v.len()))
                            .collect::<HashMap<_, _>>()
                    }),
                )
                .field("body", &result.body.len())
                .finish(),
            RouterCacheResult::RouteResult(result) => f
                .debug_struct("RouteResult")
                .field(
                    "headers",
                    &result
                        .headers
                        .headers
                        .headers
                        .iter()
                        .map(|(k, v)| (k, v.len()))
                        .collect::<HashMap<_, _>>(),
                )
                .field("body", &result.body.len())
                .finish(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CacheEntry<V> {
    // We can also { CacheEntry<K, V> => Arc<DashMap<K, V>> }, if K would be different from RouteTableKey.
    inner: Arc<DashMap<RouteTableKey, V>>,
}

impl<V> CacheEntry<V>
where
    V: Clone,
{
    /// We have to clone as we cannot return something from the Cache as a reference as it could be removed from the cache in the meantime.
    pub fn get(&self, key: &RouteTableKey) -> Option<V> {
        self.inner.get(key).map(|v| v.clone()).inspect(|_| {
            info!("[CACHE] Getting value for key: {:?}", key);
        })
    }

    pub fn set(&self, key: RouteTableKey, value: V) -> Option<V> {
        self.inner.insert(key, value)
    }

    pub fn remove(&self, key: &RouteTableKey) -> Option<(RouteTableKey, V)> {
        self.inner.remove(key)
    }
}

/// A cache for storing route results. We had to declare the Owned API types here to avoid lifetimes issues, as the cache needs to live for static lifetime.
/// and we cannot guarantee that with the `RouteResult` type.
#[derive(Debug, Clone)]
pub struct RouterCache {
    routes: CacheEntry<RouterCacheResult>,
    /// Unlike the `Middleware` struct, we are separating the `middleware` and `middleware_segments` caches, for simplicity
    middleware: CacheEntry<OwnedMiddlewareHandlerResult>,
    /// Unlike the `Middleware` struct, we are separating the `middleware` and `middleware_segments` caches, for simplicity
    /// The signature is the same as in the `middleware`, but we need the separation of the instances
    middleware_segments: CacheEntry<OwnedMiddlewareHandlerResult>,
}

static ROUTER_CACHE: Lazy<RouterCache> = Lazy::new(RouterCache::default);

// I think Default would be more idiomatic that implementing the `new` method, as we are not passing any parameters to the constructor.
impl Default for RouterCache {
    fn default() -> Self {
        RouterCache {
            routes: CacheEntry {
                inner: Arc::new(DashMap::new()),
            },
            middleware: CacheEntry {
                inner: Arc::new(DashMap::new()),
            },
            middleware_segments: CacheEntry {
                inner: Arc::new(DashMap::new()),
            },
        }
    }
}

impl RouterCache {
    pub fn debug() -> String {
        return format!("{:#?}", ROUTER_CACHE);
    }

    pub fn routes() -> &'static CacheEntry<RouterCacheResult> {
        &ROUTER_CACHE.routes
    }

    pub fn middleware() -> &'static CacheEntry<OwnedMiddlewareHandlerResult> {
        &ROUTER_CACHE.middleware
    }

    pub fn middleware_segments() -> &'static CacheEntry<OwnedMiddlewareHandlerResult> {
        &ROUTER_CACHE.middleware_segments
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
            body: self.body.as_ref().map(|b| Cow::from(b.as_slice())),
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

#[derive(Clone)]
pub struct OwnedRouteContext {
    pub request: OwnedHttpRequest,
    pub response_headers: OwnedHttpResponseHeaders,
    pub key: RouteTableKey,
    pub database: Option<Arc<Mutex<Database>>>,
    pub database_config: Option<DatabaseConfigEntry>,
}

impl std::fmt::Debug for OwnedRouteContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedRouteContext")
            .field(
                "request",
                &self
                    .request
                    .headers
                    .headers
                    .headers
                    .iter()
                    .map(|(k, v)| (k, v.len()))
                    .collect::<HashMap<_, _>>(),
            )
            .field(
                "response_headers",
                &self
                    .response_headers
                    .headers
                    .headers
                    .iter()
                    .map(|(k, v)| (k, v.len()))
                    .collect::<HashMap<_, _>>(),
            )
            .field("key", &self.key)
            .field("database", &self.database.is_some())
            .field("database_config", &self.database_config.is_some())
            .finish()
    }
}

impl OwnedRouteContext {
    pub fn to_borrowed(&self) -> RouteContext {
        let start = std::time::Instant::now();

        let ctx = RouteContext {
            request: self.request.to_borrowed(),
            response_headers: self.response_headers.to_borrowed(),
            key: &self.key,
            database: self.database.as_ref().map(|d| Arc::clone(&d)),
            database_config: self.database_config.clone(),
        };

        info!(
            "Converted OwnedRouteContext to RouteContext took: {:?} µs",
            start.elapsed().as_micros()
        );

        ctx
    }

    pub fn get_key(&self) -> &RouteTableKey {
        &self.key
    }
}

#[derive(Clone, Debug)]
pub struct OwnedRouteHandlerResult {
    pub headers: OwnedHttpResponseHeaders,
    pub body: String,
}

impl OwnedRouteHandlerResult {
    pub fn to_borrowed<'a>(&'a self) -> RouteHandlerResult<'a> {
        let start = std::time::Instant::now();

        let r = RouteHandlerResult {
            headers: self.headers.to_borrowed(),
            body: Cow::from(&self.body),
        };

        info!(
            "Converted OwnedRouteHandlerResult to RouteHandlerResult took: {:?} µs",
            start.elapsed().as_micros()
        );

        r
    }
}

#[derive(Clone, Debug)]
pub struct OptionalOwnedRouteHandlerResult {
    /// We are keeping it as optional, as the AppController handlers do not have to define headers in the cached output, although it could if it is costly to compute them.
    /// Keep in mind that the headers would have to be in-place initialized there and do not rely on the `response_headers` filed on the `OwnedRouteContext` struct,
    /// as they could not even be related.
    ///
    /// If we would want to carry some headers here, we would include them in the OwnedRouteHandlerResult later on.
    pub headers: Option<OwnedHttpResponseHeaders>,
    /// We actually have to keep the body as mandatory, and we will treat it in the AppController as the return type of the particular handler.
    pub body: String,
}
